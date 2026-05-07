"""Input validation gap detection."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class MissingValidationRule(Rule):
    """Check if tool functions directly use parameters without validation."""

    rule_id = "VAL-001"
    title = "Missing Input Validation"
    severity = "HIGH"
    cwe_id = "CWE-20"
    cwe_name = "Improper Input Validation"
    owasp = "A03:2021"
    remediation = "Validate all inputs against strict schemas. Reject unexpected data types and values."

    _DANGEROUS_ATTRS = {"open", "write", "run", "call", "Popen", "system", "eval", "exec"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            param_names = {arg.arg for arg in node.args.args}
            if not param_names:
                continue

            validated = self._find_validated_params(node)
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call):
                    if self._is_dangerous_call(stmt):
                        for arg in ast.walk(stmt):
                            if isinstance(arg, ast.Name) and arg.id in param_names:
                                if arg.id not in validated:
                                    line = getattr(stmt, "lineno", 1)
                                    col = getattr(stmt, "col_offset", 0)
                                    snippet = (
                                        source_lines[line - 1].strip()
                                        if line <= len(source_lines)
                                        else ""
                                    )
                                    yield self.make_finding(
                                        f"Parameter '{arg.id}' used in dangerous call without validation.",
                                        path, line, col, snippet,
                                    )
                                    break

    def _find_validated_params(self, func: ast.FunctionDef) -> set[str]:
        validated: set[str] = set()
        for stmt in ast.walk(func):
            if isinstance(stmt, ast.Call):
                if isinstance(stmt.func, ast.Name) and stmt.func.id == "isinstance":
                    for arg in stmt.args:
                        if isinstance(arg, ast.Name):
                            validated.add(arg.id)
                if isinstance(stmt.func, ast.Name) and stmt.func.id in {"len", "str", "int"}:
                    for arg in stmt.args:
                        if isinstance(arg, ast.Name):
                            validated.add(arg.id)
        return validated

    def _is_dangerous_call(self, call: ast.Call) -> bool:
        if isinstance(call.func, ast.Attribute):
            return call.func.attr in self._DANGEROUS_ATTRS
        if isinstance(call.func, ast.Name):
            return call.func.id in self._DANGEROUS_ATTRS
        return False


class UnsafeTypeConversionRule(Rule):
    """Detect unsafe type conversions that may crash or leak info."""

    rule_id = "VAL-002"
    title = "Unsafe Type Conversion"
    severity = "LOW"
    cwe_id = "CWE-681"
    cwe_name = "Incorrect Conversion between Numeric Types"
    owasp = "A03:2021"
    remediation = "Validate input before type conversion. Use try/except and provide meaningful error messages."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"int", "float", "bool"}:
                    if node.args and isinstance(node.args[0], ast.Name):
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0)
                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        yield self.make_finding(
                            f"Unsafe conversion of variable to {node.func.id} without validation.",
                            path, line, col, snippet,
                        )
