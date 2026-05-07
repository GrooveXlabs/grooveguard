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
    cwe_id = "CWE-78"
    cwe_name = "OS Command Injection"
    owasp = "A03:2021"
    remediation = "Use parameterized APIs. Avoid shell=True. Validate and sanitize all inputs."

    _DANGEROUS = {"subprocess.call", "subprocess.run", "subprocess.Popen", "os.system", "os.popen", "eval", "exec"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name in self._DANGEROUS:
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Dangerous function '{func_name}' called.",
                        path, line, col, snippet,
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
    cwe_id = "CWE-22"
    cwe_name = "Path Traversal"
    owasp = "A01:2021"
    remediation = "Use allowlists for permitted paths. Validate and canonicalize all path inputs."

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
                        # Check if path contains user input (f-string, variable, format)
                        path_arg = node.args[0] if node.args else None
                        if path_arg and self._is_user_controlled(path_arg):
                            line = getattr(node, "lineno", 1)
                            col = getattr(node, "col_offset", 0)
                            snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                            yield self.make_finding(
                                "File opened in write/append mode with user-controlled path — path traversal risk.",
                                path, line, col, snippet,
                            )

    @staticmethod
    def _get_mode(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant):
            return node.value
        return None

    @staticmethod
    def _is_user_controlled(node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "replace", "join"}:
                return True
        return False


class DangerousToolRule(Rule):
    """Flag MCP tool definitions with overly broad capabilities."""

    rule_id = "DNG-003"
    title = "Overly Permissive Tool Definition"
    severity = "MEDIUM"
    cwe_id = "CWE-94"
    cwe_name = "Code Injection"
    owasp = "A03:2021"
    remediation = "Restrict tool capabilities to the minimum required scope."

    _DESCRIPTORS = ["run_command", "execute", "shell", "system", "exec_code", "eval_code"]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                name = node.name.lower()
                if any(desc in name for desc in self._DESCRIPTORS):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        f"Tool function '{node.name}' suggests dangerous capability.",
                        path, line, col, snippet,
                    )


class PathTraversalRule(Rule):
    """Detect potential path traversal via os.path.join with user input."""

    rule_id = "DNG-004"
    title = "Path Traversal"
    severity = "HIGH"
    cwe_id = "CWE-22"
    cwe_name = "Path Traversal"
    owasp = "A01:2021"
    remediation = "Use allowlists for permitted paths. Validate and canonicalize all path inputs."

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ShellExecRule._get_call_name(node.func)
                if func_name in {"os.path.join", "pathlib.Path", "Path"}:
                    # If any arg is a Name (variable), flag it
                    for arg in node.args[1:]:
                        if isinstance(arg, ast.Name):
                            line = getattr(node, "lineno", 1)
                            col = getattr(node, "col_offset", 0)
                            snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                            yield self.make_finding(
                                f"Path construction with variable '{arg.id}' — potential path traversal.",
                                path, line, col, snippet,
                            )
                            break
