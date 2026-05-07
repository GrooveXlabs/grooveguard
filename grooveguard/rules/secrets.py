"""Secret detection rules with entropy analysis."""

from __future__ import annotations

import ast
import math
import re
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class ApiKeyRule(Rule):
    """Detect hardcoded API keys in string literals and assignments."""

    rule_id = "SEC-001"
    title = "Hardcoded API Key"
    severity = "CRITICAL"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A07:2021"
    remediation = "Store credentials in environment variables, secret managers, or encrypted configuration files."

    _PATTERNS = [
        re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),  # OpenAI
        re.compile(r"[a-zA-Z0-9]{32,}-[a-zA-Z0-9]{10,}", re.IGNORECASE),  # Generic
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),  # AWS
        re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE),  # GitHub
        re.compile(r"glpat-[a-zA-Z0-9\-]{20}", re.IGNORECASE),  # GitLab
        re.compile(r"sq0csp-[0-9A-Za-z\-_]{43}", re.IGNORECASE),  # Square
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
                        yield self.make_finding(
                            f"Hardcoded API key detected: {snippet[:60]}...",
                            path, line, col, snippet,
                        )
                        break


class SecretTokenRule(Rule):
    """Detect hardcoded secret tokens in assignments."""

    rule_id = "SEC-002"
    title = "Hardcoded Secret Token"
    severity = "CRITICAL"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A07:2021"
    remediation = "Store credentials in environment variables, secret managers, or encrypted configuration files."

    _KEYWORDS = ["secret", "token", "api_key", "apikey", "auth_token", "access_token"]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(kw in name for kw in self._KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                yield self.make_finding(
                                    f"Hardcoded secret assigned to variable '{target.id}'.",
                                    path, line, col, snippet,
                                )


class HardcodedPasswordRule(Rule):
    """Detect hardcoded passwords."""

    rule_id = "SEC-003"
    title = "Hardcoded Password"
    severity = "HIGH"
    cwe_id = "CWE-259"
    cwe_name = "Use of Hard-coded Password"
    owasp = "A07:2021"
    remediation = "Use environment variables or a secrets manager for passwords."

    _KEYWORDS = ["password", "passwd", "pwd"]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(kw in name for kw in self._KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                yield self.make_finding(
                                    f"Hardcoded password assigned to variable '{target.id}'.",
                                    path, line, col, snippet,
                                )


class HighEntropyStringRule(Rule):
    """Detect high-entropy strings that may be secrets or keys.

    Uses Shannon entropy to flag strings that look like random tokens,
    which are common patterns for API keys, JWT tokens, and encryption keys.
    """

    rule_id = "SEC-004"
    title = "High-Entropy String (Possible Secret)"
    severity = "MEDIUM"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A07:2021"
    remediation = "Review high-entropy strings for secrets. Move any secrets to environment variables or a secret manager."

    MIN_LENGTH = 20
    MIN_ENTROPY = 4.5
    MAX_ENTROPY = 6.5  # Avoid flagging base64 of normal text

    # Skip common non-secret patterns
    _SKIP_PATTERNS = [
        re.compile(r"^[a-f0-9]{32,}$", re.IGNORECASE),  # Likely a UUID or hash
        re.compile(r"^\d+$"),  # All digits
        re.compile(r"^https?://"),  # URLs
        re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$"),  # Identifiers
    ]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if len(value) < self.MIN_LENGTH:
                    continue
                if any(pat.match(value) for pat in self._SKIP_PATTERNS):
                    continue
                entropy = self._shannon_entropy(value)
                if self.MIN_ENTROPY <= entropy <= self.MAX_ENTROPY:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"High-entropy string detected (entropy={entropy:.2f}) — possible secret or API key.",
                        path, line, col, snippet,
                    )

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy


class JwtSecretRule(Rule):
    """Detect hardcoded JWT secrets."""

    rule_id = "SEC-005"
    title = "Hardcoded JWT Secret"
    severity = "CRITICAL"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A07:2021"
    remediation = "Store JWT secrets in environment variables or a secret manager. Rotate secrets regularly."

    _KEYWORDS = ["jwt_secret", "jwt_key", "secret_key", "flask_secret", "django_secret"]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(kw in name for kw in self._KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                yield self.make_finding(
                                    f"Hardcoded JWT/secret key assigned to '{target.id}'.",
                                    path, line, col, snippet,
                                )


class DatabaseUriRule(Rule):
    """Detect hardcoded database connection strings with credentials."""

    rule_id = "SEC-006"
    title = "Hardcoded Database Credentials"
    severity = "CRITICAL"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A07:2021"
    remediation = "Use environment variables or a secret manager for database credentials."

    _PATTERN = re.compile(r"(postgresql|mysql|mongodb|redis|sqlite)://[^:]+:[^@]+@")

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if self._PATTERN.search(value):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        "Database connection string with embedded credentials detected.",
                        path, line, col, snippet,
                    )


class PrivateKeyRule(Rule):
    """Detect hardcoded private keys or certificates."""

    rule_id = "SEC-007"
    title = "Hardcoded Private Key"
    severity = "CRITICAL"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A07:2021"
    remediation = "Store private keys in HSM, secret manager, or encrypted files. Never commit to version control."

    _KEY_MARKERS = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
    ]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                for marker in self._KEY_MARKERS:
                    if marker in value:
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0)
                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        yield self.make_finding(
                            f"Hardcoded private key detected ({marker}).",
                            path, line, col, snippet,
                        )
                        break


class BearerTokenRule(Rule):
    """Detect hardcoded Bearer tokens in string literals."""

    rule_id = "SEC-008"
    title = "Hardcoded Bearer Token"
    severity = "CRITICAL"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A07:2021"
    remediation = "Store tokens in environment variables or a secret manager."

    _PATTERN = re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE)

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if self._PATTERN.search(value):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        "Hardcoded Bearer token detected.",
                        path, line, col, snippet,
                    )
