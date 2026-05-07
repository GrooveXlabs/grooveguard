"""SSRF detection rules."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class UnvalidatedUrlFetchRule(Rule):
    """Detect tools that fetch URLs without validating them."""

    rule_id = "SSRF-001"
    title = "Unvalidated URL Fetch"
    severity = "HIGH"
    cwe_id = "CWE-918"
    cwe_name = "Server-Side Request Forgery"
    owasp = "A10:2021"
    remediation = "Use allowlists for permitted URLs. Block internal IPs and metadata endpoints."

    _FETCH_ATTRS = {"get", "post", "put", "patch", "delete", "request"}
    _FETCH_MODULES = {"requests", "httpx", "urllib", "urllib.request", "aiohttp"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_unvalidated_fetch(node):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield self.make_finding(
                        "URL fetch without validation — potential SSRF.",
                        path, line, col, snippet,
                    )

    def _is_unvalidated_fetch(self, call: ast.Call) -> bool:
        if not isinstance(call.func, ast.Attribute):
            return False
        if call.func.attr not in self._FETCH_ATTRS:
            return False
        if not call.args:
            return False

        base = call.func.value
        while isinstance(base, ast.Attribute):
            base = base.value

        if isinstance(base, ast.Name):
            http_names = {"requests", "httpx", "urllib", "aiohttp", "client", "session", "http"}
            if base.id in http_names:
                first_arg = call.args[0]
                if isinstance(first_arg, ast.Name):
                    return True
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    return True
        return False
