"""Insecure API usage rules for GrooveGuard.

Detects dangerous deserialization, unsafe YAML/XML parsing, temp file issues,
and other API misuse patterns.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class PickleRule(Rule):
    """Detect unsafe pickle.loads() and pickle.load() usage."""

    rule_id = "DNG-005"
    title = "Unsafe Deserialization (pickle)"
    severity = "CRITICAL"
    cwe_id = "CWE-502"
    cwe_name = "Deserialization of Untrusted Data"
    owasp = "A08:2021"
    remediation = "Avoid deserializing untrusted data with pickle. Use JSON instead."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "dill.load", "dill.loads"}:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Unsafe deserialization via '{func_name}' — arbitrary code execution risk.",
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


class YamlLoadRule(Rule):
    """Detect unsafe yaml.load() without Loader=yaml.SafeLoader."""

    rule_id = "DNG-006"
    title = "Unsafe YAML Loading"
    severity = "CRITICAL"
    cwe_id = "CWE-502"
    cwe_name = "Deserialization of Untrusted Data"
    owasp = "A08:2021"
    remediation = "Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader)."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"yaml.load", "yaml.unsafe_load"}:
                    has_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == "Loader":
                            loader_name = self._get_call_name(kw.value) if isinstance(kw.value, (ast.Name, ast.Attribute)) else ""
                            if "SafeLoader" in loader_name or "BaseLoader" in loader_name:
                                has_safe_loader = True
                                break
                    if not has_safe_loader:
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0)
                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        yield self.make_finding(
                            "yaml.load() called without SafeLoader — arbitrary code execution risk.",
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


class MarshalRule(Rule):
    """Detect unsafe marshal.loads() usage."""

    rule_id = "DNG-008"
    title = "Unsafe marshal Usage"
    severity = "HIGH"
    cwe_id = "CWE-502"
    cwe_name = "Deserialization of Untrusted Data"
    owasp = "A08:2021"
    remediation = "Avoid marshal for untrusted data. Use JSON or msgpack."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"marshal.load", "marshal.loads"}:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Unsafe deserialization via '{func_name}' — arbitrary code execution risk.",
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


class TempFileRule(Rule):
    """Detect insecure temporary file creation."""

    rule_id = "DNG-007"
    title = "Insecure Temporary File"
    severity = "MEDIUM"
    cwe_id = "CWE-377"
    cwe_name = "Insecure Temporary File"
    owasp = "A01:2021"
    remediation = "Use tempfile.mkstemp() or NamedTemporaryFile() with proper permissions."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"tempfile.mktemp", "os.tmpnam", "os.tempnam", "mktemp", "tmpnam", "tempnam"}:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Insecure temporary file function '{func_name}' detected — race condition risk.",
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


class AssertStatementRule(Rule):
    """Detect assert statements that may be stripped in optimized bytecode."""

    rule_id = "DNG-009"
    title = "Assert Statement in Security Check"
    severity = "MEDIUM"
    cwe_id = "CWE-617"
    cwe_name = "Reachable Assertion"
    owasp = "A05:2021"
    remediation = "Use explicit if/raise instead of assert for security checks. Asserts are stripped with -O."

    _SECURITY_KEYWORDS = {"auth", "login", "password", "token", "secret", "permission", "admin", "role"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                # Check if the assertion test contains security-related terms
                test_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                if any(kw in test_str.lower() for kw in self._SECURITY_KEYWORDS):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        "Assert used for security check — assert statements are stripped with -O flag.",
                        path, line, col, snippet,
                    )


class DebugModeRule(Rule):
    """Detect debug mode enabled in production code."""

    rule_id = "DNG-010"
    title = "Debug Mode Enabled"
    severity = "HIGH"
    cwe_id = "CWE-489"
    cwe_name = "Active Debug Code"
    owasp = "A05:2021"
    remediation = "Disable debug mode in production. Use environment variables to control debug state."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if name in {"debug", "app_debug", "flask_debug", "django_debug"}:
                            if isinstance(node.value, ast.Constant) and node.value.value is True:
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                yield self.make_finding(
                                    f"Debug mode enabled ({target.id} = True). Disable in production.",
                                    path, line, col, snippet,
                                )

            if isinstance(node, ast.Attribute):
                if node.attr == "debug":
                    parent = None
                    # Walk up to find assignment
                    for parent_node in ast.walk(tree):
                        if isinstance(parent_node, ast.Assign):
                            if node in ast.walk(parent_node):
                                if isinstance(parent_node.value, ast.Constant) and parent_node.value.value is True:
                                    line = getattr(parent_node, "lineno", 1)
                                    col = getattr(parent_node, "col_offset", 0)
                                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                    yield self.make_finding(
                                        "Debug mode enabled (app.debug = True). Disable in production.",
                                        path, line, col, snippet,
                                    )


class XmlExternalEntityRule(Rule):
    """Detect XML parsing with external entity expansion enabled."""

    rule_id = "XML-001"
    title = "XML External Entity (XXE)"
    severity = "HIGH"
    cwe_id = "CWE-611"
    cwe_name = "Improper Restriction of XML External Entity Reference"
    owasp = "A05:2021"
    remediation = "Disable external entities and DTDs in XML parsers. Use defusedxml."

    _DANGEROUS_PARSERS = {
        "xml.etree.ElementTree.parse",
        "xml.dom.minidom.parse",
        "xml.dom.minidom.parseString",
        "xml.sax.make_parser",
        "lxml.etree.parse",
        "lxml.etree.fromstring",
    }

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in self._DANGEROUS_PARSERS:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"XML parser '{func_name}' may be vulnerable to XXE. Use defusedxml or disable external entities.",
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


class SslVerificationDisabledRule(Rule):
    """Detect SSL/TLS certificate verification disabled."""

    rule_id = "NET-001"
    title = "SSL Verification Disabled"
    severity = "HIGH"
    cwe_id = "CWE-295"
    cwe_name = "Improper Certificate Validation"
    owasp = "A02:2021"
    remediation = "Always verify SSL certificates. Do not disable certificate validation in production."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if "requests" in func_name or "httpx" in func_name or "urllib" in func_name:
                    for kw in node.keywords:
                        if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            line = getattr(node, "lineno", 1)
                            col = getattr(node, "col_offset", 0)
                            snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                            yield self.make_finding(
                                f"SSL certificate verification disabled in '{func_name}' — MITM risk.",
                                path, line, col, snippet,
                            )

            # ssl._create_unverified_context()
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if "_create_unverified_context" in func_name:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        "Unverified SSL context created — MITM risk.",
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


class CorsWildcardRule(Rule):
    """Detect overly permissive CORS configuration."""

    rule_id = "NET-003"
    title = "Permissive CORS Configuration"
    severity = "MEDIUM"
    cwe_id = "CWE-346"
    cwe_name = "Origin Validation Error"
    owasp = "A05:2021"
    remediation = "Restrict CORS to specific trusted origins. Never use '*' with credentials."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if "cors" in target.id.lower() or "origin" in target.id.lower():
                            if isinstance(node.value, ast.Constant) and node.value.value == "*":
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                yield self.make_finding(
                                    f"Overly permissive CORS: {target.id} = '*'.",
                                    path, line, col, snippet,
                                )


class HardcodedIpRule(Rule):
    """Detect hardcoded IP addresses (potential backdoors or test data)."""

    rule_id = "NET-004"
    title = "Hardcoded IP Address"
    severity = "LOW"
    cwe_id = "CWE-798"
    cwe_name = "Use of Hard-coded Credentials"
    owasp = "A05:2021"
    remediation = "Use configuration files or environment variables for IP addresses."

    _IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        import re
        compiled = re.compile(self._IP_PATTERN)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if compiled.search(node.value):
                    # Skip common safe IPs
                    if any(safe in node.value for safe in {"127.0.0.1", "0.0.0.0", "255.255.255.255"}):
                        continue
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Hardcoded IP address detected: {node.value}",
                        path, line, col, snippet,
                    )


class LoggingSensitiveDataRule(Rule):
    """Detect potential logging of sensitive data."""

    rule_id = "LOG-001"
    title = "Sensitive Data in Log"
    severity = "MEDIUM"
    cwe_id = "CWE-532"
    cwe_name = "Insertion of Sensitive Information into Log File"
    owasp = "A09:2021"
    remediation = "Redact passwords, tokens, and PII from logs. Use structured logging with field filtering."

    _SENSITIVE_PATTERNS = {"password", "secret", "token", "api_key", "apikey", "credential", "auth"}
    _LOG_FUNCTIONS = {"print", "logging.info", "logging.debug", "logging.warning", "logging.error", "logger.info", "logger.debug", "logger.warning", "logger.error"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in self._LOG_FUNCTIONS or "log" in func_name.lower() or "print" in func_name.lower():
                    for arg in ast.walk(node):
                        if isinstance(arg, ast.Name):
                            if any(pattern in arg.id.lower() for pattern in self._SENSITIVE_PATTERNS):
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                yield self.make_finding(
                                    f"Potential sensitive data ({arg.id}) logged — redact before logging.",
                                    path, line, col, snippet,
                                )
                                break

    def _get_call_name(self, node: ast.expr) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))
