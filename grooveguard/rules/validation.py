"""Input validation gap detection."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class MissingValidationRule(Rule):
    """Check if tool functions directly use parameters without validation.

    Heuristic: If a parameter is used in a dangerous call (e.g., open, requests.get)
    and there is no isinstance() or length/type check before that call, flag it.
    """

    rule_id = "VAL-001"
    title = "Missing Input Validation"
    severity = "HIGH"

    _DANGEROUS_ATTRS = {"open", "read", "write", "get", "post", "put", "delete", "run", "call", "Popen"}

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
                                    yield Finding(
                                        rule_id=self.rule_id,
                                        title=self.title,
                                        severity=self.severity,
                                        message=f"Parameter '{arg.id}' used in dangerous call without validation.",
                                        file=path,
                                        line=line,
                                        column=col,
                                        snippet=snippet,
                                    )
                                    break

    def _find_validated_params(self, func: ast.FunctionDef) -> set[str]:
        """Find parameters that appear in isinstance checks or explicit validation."""
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
