"""Cryptographic weakness detection rules."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class WeakHashRule(Rule):
    """Detect use of weak hash algorithms (MD5, SHA1)."""

    rule_id = "CRY-001"
    title = "Weak Hash Algorithm"
    severity = "HIGH"
    cwe_id = "CWE-328"
    cwe_name = "Use of Weak Hash"
    owasp = "A02:2021"
    remediation = "Use SHA-256 or stronger for integrity. Use bcrypt/Argon2id for passwords."

    _WEAK_HASHES = {"md5", "sha1", "sha", "MD5", "SHA1", "SHA"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"hashlib.md5", "hashlib.sha1", "hashlib.sha", "md5", "sha1", "sha"}:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Weak hash algorithm '{func_name}' detected. Use SHA-256+ or bcrypt/Argon2id.",
                        path, line, col, snippet,
                    )
                # hashlib.new('md5')
                if func_name in {"hashlib.new", "new"}:
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if arg.value.lower() in self._WEAK_HASHES:
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                yield self.make_finding(
                                    f"Weak hash algorithm '{arg.value}' specified in hashlib.new().",
                                    path, line, col, snippet,
                                )

    def _get_call_name(self, node: ast.expr) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))


class WeakCryptoRule(Rule):
    """Detect use of weak or deprecated cryptographic algorithms."""

    rule_id = "CRY-002"
    title = "Weak Cryptographic Algorithm"
    severity = "HIGH"
    cwe_id = "CWE-327"
    cwe_name = "Use of Broken Cryptographic Algorithm"
    owasp = "A02:2021"
    remediation = "Use AES-256-GCM, ChaCha20-Poly1305. Avoid DES, 3DES, Blowfish, RSA < 2048."

    _WEAK_ALGORITHMS = {
        "DES", "TripleDES", "Blowfish", "ARC2", "ARC4", "CAST",
        "des", "tripledes", "blowfish", "arc2", "arc4", "cast",
    }

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                parts = func_name.split(".")
                if any(part in self._WEAK_ALGORITHMS for part in parts):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Weak cryptographic algorithm '{func_name}' detected.",
                        path, line, col, snippet,
                    )

    def _get_call_name(self, node: ast.expr) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))


class InsecureRandomRule(Rule):
    """Detect use of insecure random number generators."""

    rule_id = "CRY-003"
    title = "Insecure Random Number Generator"
    severity = "MEDIUM"
    cwe_id = "CWE-338"
    cwe_name = "Use of Cryptographically Weak PRNG"
    owasp = "A02:2021"
    remediation = "Use secrets.token_hex(), secrets.token_urlsafe(), or random.SystemRandom for security-critical randomness."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"random.random", "random.randint", "random.choice", "random.shuffle", "random.sample"}:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Insecure random '{func_name}' used for potentially security-sensitive operation.",
                        path, line, col, snippet,
                    )

    def _get_call_name(self, node: ast.expr) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))
