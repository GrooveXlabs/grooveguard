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

    _FETCH_ATTRS = {"get", "post", "put", "patch", "delete", "request"}
    _FETCH_MODULES = {"requests", "httpx", "urllib", "urllib.request", "aiohttp"}

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if self._is_unvalidated_fetch(node):
                    line = getattr(node, "lineno", 1)
                    col = getattr(node, "col_offset", 0)
                    snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                    yield Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        severity=self.severity,
                        message="URL fetch without validation — potential SSRF.",
                        file=path,
                        line=line,
                        column=col,
                        snippet=snippet,
                    )

    def _is_unvalidated_fetch(self, call: ast.Call) -> bool:
        if isinstance(call.func, ast.Attribute):
            if call.func.attr in self._FETCH_ATTRS:
                if call.args:
                    first_arg = call.args[0]
                    if isinstance(first_arg, ast.Name):
                        return True
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        return True
        return False
