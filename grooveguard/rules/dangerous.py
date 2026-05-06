"""Dangerous capability rules."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class ShellExecRule(Rule):
    """Detect calls to subprocess, os.system, or eval/exec."""

    rule_id = "DNG-001"
    title = "Shell Command Execution"
    severity = "CRITICAL"

    _DANGEROUS = {"subprocess.call", "subprocess.run", "subprocess.Popen", "os.system", "eval", "exec"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in self._DANGEROUS:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        message=f"Dangerous function '{func_name}' called.",
                        file=path,
                        line=line,
                        column=col,
                        snippet=snippet,
                    )

    @staticmethod
    def _get_call_name(node: ast.expr) -> str:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))


class FileWriteRule(Rule):
    """Detect unrestricted file write operations."""

    rule_id = "DNG-002"
    title = "Unrestricted File Write"
    severity = "HIGH"

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ShellExecRule._get_call_name(node.func)
                if func_name in {"open", "builtins.open"}:
                    if len(node.args) >= 2:
                        mode = self._get_mode(node.args[1])
                    elif any(kw.arg == "mode" for kw in node.keywords):
                        mode = next(
                            kw.value.value
                            for kw in node.keywords
                            if kw.arg == "mode" and isinstance(kw.value, ast.Constant)
                        )
                    else:
                        mode = "r"
                    if isinstance(mode, str) and ("w" in mode or "a" in mode):
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0)
                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        yield Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            message=f"File opened in write/append mode without validation.",
                            file=path,
                            line=line,
                            column=col,
                            snippet=snippet,
                        )

    @staticmethod
    def _get_mode(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant):
            return node.value
        return None


class DangerousToolRule(Rule):
    """Flag MCP tool definitions with overly broad capabilities."""

    rule_id = "DNG-003"
    title = "Overly Permissive Tool Definition"
    severity = "MEDIUM"

    _DESCRIPTORS = ["run_command", "execute", "shell", "system", "exec_code", "eval_code"]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                name = node.name.lower()
                if any(desc in name for desc in self._DESCRIPTORS):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        message=f"Tool function '{node.name}' suggests dangerous capability.",
                        file=path,
                        line=line,
                        column=col,
                        snippet=snippet,
                    )
