"""Injection vulnerability rules for GrooveGuard.

Covers SQL injection, XSS, command injection, code injection, and
template injection.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class SqlInjectionRule(Rule):
    """Detect SQL injection via string formatting or concatenation."""

    rule_id = "INJ-001"
    title = "SQL Injection"
    severity = "CRITICAL"
    cwe_id = "CWE-89"
    cwe_name = "SQL Injection"
    owasp = "A03:2021"
    remediation = "Use parameterized queries or ORM. Never concatenate user input into SQL."

    _SQL_KEYWORDS = {"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"}
    _DANGEROUS_METHODS = {"format", "%", "join", "+"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # cursor.execute(f"SELECT * FROM {user_input}")
                func_name = self._get_call_name(node.func)
                if func_name and "execute" in func_name.lower():
                    for arg in node.args:
                        if self._is_user_controlled(arg):
                            line = getattr(node, "lineno", 1)
                            col = getattr(node, "col_offset", 0)
                            snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                            yield self.make_finding(
                                f"SQL query may contain user-controlled input via '{func_name}'.",
                                path, line, col, snippet,
                            )

            # f"SELECT * FROM {table}" where table is a parameter
            if isinstance(node, ast.JoinedStr):
                if self._has_sql_keywords(node):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        "SQL query uses f-string formatting which can lead to injection.",
                        path, line, col, snippet,
                    )

            # "SELECT * FROM %s" % user_input
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if self._is_sql_string(node.left):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        "SQL query uses %-formatting which can lead to injection.",
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

    def _is_user_controlled(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, ast.BinOp):
            return True
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "replace"}:
                return True
        return False

    def _has_sql_keywords(self, node: ast.JoinedStr) -> bool:
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                upper = value.value.upper()
                if any(kw in upper for kw in self._SQL_KEYWORDS):
                    return True
        return False

    def _is_sql_string(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            upper = node.value.upper()
            return any(kw in upper for kw in self._SQL_KEYWORDS)
        return False


class XssRule(Rule):
    """Detect potential Cross-Site Scripting vulnerabilities."""

    rule_id = "INJ-002"
    title = "Cross-Site Scripting (XSS)"
    severity = "HIGH"
    cwe_id = "CWE-79"
    cwe_name = "Cross-site Scripting"
    owasp = "A03:2021"
    remediation = "Encode all output contextually. Use CSP headers. Validate and sanitize input."

    _DANGEROUS_FUNCTIONS = {
        "render_template_string", "render_template_string",
        "mark_safe", "make_response", "Response",
    }

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in self._DANGEROUS_FUNCTIONS:
                    for arg in node.args:
                        if self._contains_user_input(arg):
                            line = getattr(node, "lineno", 1)
                            col = getattr(node, "col_offset", 0)
                            snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                            yield self.make_finding(
                                f"Potential XSS: user input passed to '{func_name}' without escaping.",
                                path, line, col, snippet,
                            )

            # Autoescape disabled
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"jinja2.Environment", "Environment"}:
                    for kw in node.keywords:
                        if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                            line = getattr(node, "lineno", 1)
                            col = getattr(node, "col_offset", 0)
                            snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                            yield self.make_finding(
                                "Jinja2 autoescape is disabled. This enables XSS attacks.",
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

    def _contains_user_input(self, node: ast.expr) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                return True
            if isinstance(child, ast.Attribute):
                return True
        return False


class CommandInjectionRule(Rule):
    """Detect command injection via shell=True or string formatting in subprocess."""

    rule_id = "INJ-003"
    title = "Command Injection"
    severity = "CRITICAL"
    cwe_id = "CWE-78"
    cwe_name = "OS Command Injection"
    owasp = "A03:2021"
    remediation = "Use parameterized APIs. Avoid shell=True. Validate and sanitize all inputs."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "os.system", "os.popen", "popen"}:
                    # Check for shell=True
                    shell_true = False
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            shell_true = True
                            break

                    if shell_true:
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0)
                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        yield self.make_finding(
                            f"'{func_name}' called with shell=True — command injection risk.",
                            path, line, col, snippet,
                        )
                    # Check first arg for string formatting
                    elif node.args and self._is_formatted_string(node.args[0]):
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0)
                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        yield self.make_finding(
                            f"'{func_name}' called with formatted string — potential command injection.",
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

    def _is_formatted_string(self, node: ast.expr) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        return False


class EvalExecRule(Rule):
    """Detect dangerous use of eval(), exec(), and compile()."""

    rule_id = "INJ-004"
    title = "Dangerous Code Execution"
    severity = "CRITICAL"
    cwe_id = "CWE-94"
    cwe_name = "Code Injection"
    owasp = "A03:2021"
    remediation = "Avoid eval(), exec(), and compile() with untrusted input. Use AST parsing for safe evaluation."

    _DANGEROUS = {"eval", "exec", "compile"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in self._DANGEROUS:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Dangerous function '{func_name}' called — code injection risk.",
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
