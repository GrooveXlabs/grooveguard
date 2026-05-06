"""MCP manifest scanner for GrooveGuard.

Scans JSON/YAML MCP server manifests for security misconfigurations,
prompt-injection risks, and overly permissive tool definitions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


try:
    import yaml

    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False


@dataclass
class ManifestFinding:
    """A security finding discovered in an MCP manifest."""

    rule_id: str
    title: str
    severity: str
    message: str
    file: Path
    tool_name: str


class ManifestScanner:
    """Scan MCP manifest files for security issues."""

    # Tool names considered too generic to be safe
    _GENERIC_NAMES: set[str] = {
        "run",
        "exec",
        "execute",
        "do",
        "call",
        "invoke",
        "process",
        "cmd",
        "command",
        "tool",
        "action",
        "handle",
        "perform",
    }

    # Tool names that suggest dangerous / overly-broad capabilities
    _DANGEROUS_NAME_PATTERNS: list[str] = [
        "shell",
        "system",
        "execute",
        "read_file",
        "write_file",
        "eval",
        "exec",
        "subprocess",
    ]

    # Name fragments that imply filesystem access
    _FILESYSTEM_HINTS: set[str] = {
        "file",
        "read",
        "write",
        "filesystem",
        "fs",
        "path",
        "dir",
        "folder",
        "delete",
        "remove",
    }

    # Name fragments that imply network access
    _NETWORK_HINTS: set[str] = {
        "http",
        "fetch",
        "request",
        "url",
        "api",
        "web",
        "network",
        "curl",
        "wget",
        "download",
        "post",
        "get",
    }

    # Prompt-injection trigger phrases (case-insensitive)
    _PROMPT_INJECTION_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"ignore\s+(previous|all\s+prior|earlier)\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(previous|all\s+prior|earlier)\s+instructions", re.IGNORECASE),
        re.compile(r"forget\s+everything", re.IGNORECASE),
        re.compile(r"do\s+not\s+follow", re.IGNORECASE),
        re.compile(r"override\s+(previous|all)\s+instructions", re.IGNORECASE),
        re.compile(r"bypass\s+(security|restrictions|filters)", re.IGNORECASE),
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_manifest(self, path: Path) -> list[ManifestFinding]:
        """Scan a single file for MCP manifest issues.

        Returns an empty list if the file does not exist, cannot be parsed,
        or does not look like an MCP manifest.
        """
        path = Path(path)
        if not path.exists() or not path.is_file():
            return []

        raw = path.read_text(encoding="utf-8")
        data = self._parse(raw, path.suffix)
        if data is None:
            return []

        if not self._is_mcp_manifest(data, path.name):
            return []

        tools = self._extract_tools(data)
        findings: list[ManifestFinding] = []

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            findings.extend(self._check_tool(tool, path))

        return findings

    def scan_directory(self, path: Path) -> list[ManifestFinding]:
        """Recursively scan a directory for MCP manifest files."""
        path = Path(path)
        if not path.exists() or not path.is_dir():
            return []

        findings: list[ManifestFinding] = []
        for candidate in path.rglob("*"):
            if candidate.is_file() and candidate.suffix.lower() in {
                ".json",
                ".yaml",
                ".yml",
            }:
                findings.extend(self.scan_manifest(candidate))
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse(raw: str, suffix: str) -> dict[str, Any] | None:
        """Attempt to parse *raw* as JSON or YAML."""
        suffix = suffix.lower()
        if suffix in {".yaml", ".yml"}:
            if not _HAS_YAML:
                return None
            try:
                parsed = yaml.safe_load(raw)
                if isinstance(parsed, dict):
                    return parsed
                return None
            except yaml.YAMLError:
                return None

        # Default to JSON for everything else (including .json and extensionless)
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _is_mcp_manifest(data: dict[str, Any], filename: str) -> bool:
        """Heuristic: does *data* look like an MCP manifest?"""
        fname = filename.lower()
        if fname in ("mcp-config.json", "mcp-server.json"):
            return True
        if "mcp" in data:
            return True
        if "tools" in data and isinstance(data.get("tools"), list):
            return True
        return False

    @staticmethod
    def _extract_tools(data: dict[str, Any]) -> list[Any]:
        """Return the list of tool definitions from a manifest dict."""
        if "tools" in data and isinstance(data["tools"], list):
            return data["tools"]
        mcp = data.get("mcp", {})
        if isinstance(mcp, dict) and "tools" in mcp and isinstance(mcp["tools"], list):
            return mcp["tools"]
        return []

    # ------------------------------------------------------------------
    # Per-tool checks
    # ------------------------------------------------------------------

    def _check_tool(self, tool: dict[str, Any], path: Path) -> list[ManifestFinding]:
        findings: list[ManifestFinding] = []
        name = tool.get("name", "")
        if not isinstance(name, str):
            name = str(name)
        description = tool.get("description", "") or ""
        if not isinstance(description, str):
            description = str(description)
        schema = tool.get("inputSchema") or tool.get("parameters") or {}
        if not isinstance(schema, dict):
            schema = {}

        findings.extend(self._check_generic_name(name, path))
        findings.extend(self._check_description(name, description, path))
        findings.extend(self._check_dangerous_name(name, path))
        findings.extend(self._check_required_fields(name, schema, path))
        findings.extend(self._check_filesystem(name, schema, path))
        findings.extend(self._check_network(name, schema, path))
        findings.extend(self._check_prompt_injection(name, description, path))

        return findings

    def _check_generic_name(self, name: str, path: Path) -> list[ManifestFinding]:
        if name.lower() in self._GENERIC_NAMES:
            return [
                ManifestFinding(
                    rule_id="MANIFEST-001",
                    title="Generic tool name",
                    severity="MEDIUM",
                    message=f"Tool '{name}' uses a generic name that may hide its true capabilities.",
                    file=path,
                    tool_name=name,
                )
            ]
        return []

    def _check_description(
        self, name: str, description: str, path: Path
    ) -> list[ManifestFinding]:
        findings: list[ManifestFinding] = []
        stripped = description.strip()
        if not stripped:
            findings.append(
                ManifestFinding(
                    rule_id="MANIFEST-002",
                    title="Missing tool description",
                    severity="HIGH",
                    message=f"Tool '{name}' has no description. Missing descriptions increase prompt-injection risk.",
                    file=path,
                    tool_name=name,
                )
            )
        elif len(stripped) < 20:
            findings.append(
                ManifestFinding(
                    rule_id="MANIFEST-003",
                    title="Tool description too short",
                    severity="MEDIUM",
                    message=f"Tool '{name}' description is too short ({len(stripped)} chars). Descriptions should be at least 20 characters.",
                    file=path,
                    tool_name=name,
                )
            )
        return findings

    def _check_dangerous_name(self, name: str, path: Path) -> list[ManifestFinding]:
        lower = name.lower()
        for pattern in self._DANGEROUS_NAME_PATTERNS:
            if pattern in lower:
                return [
                    ManifestFinding(
                        rule_id="MANIFEST-004",
                        title="Overly broad tool name",
                        severity="HIGH",
                        message=f"Tool '{name}' has an overly broad name suggesting dangerous capabilities.",
                        file=path,
                        tool_name=name,
                    )
                ]
        return []

    def _check_required_fields(
        self, name: str, schema: dict[str, Any], path: Path
    ) -> list[ManifestFinding]:
        required = schema.get("required")
        if required is None or (isinstance(required, list) and len(required) == 0):
            return [
                ManifestFinding(
                    rule_id="MANIFEST-005",
                    title="Schema missing required fields",
                    severity="MEDIUM",
                    message=f"Tool '{name}' input schema does not define any required fields, creating a validation gap.",
                    file=path,
                    tool_name=name,
                )
            ]
        return []

    def _check_filesystem(
        self, name: str, schema: dict[str, Any], path: Path
    ) -> list[ManifestFinding]:
        lower = name.lower()
        if not any(hint in lower for hint in self._FILESYSTEM_HINTS):
            return []

        props = schema.get("properties", {})
        if not isinstance(props, dict):
            props = {}

        path_params = {
            k for k in props.keys() if k.lower() in {"path", "file", "filepath", "filename", "directory", "dir"}
        }
        required = set(schema.get("required") or [])

        # No path-like parameter at all → unrestricted
        if not path_params:
            return [
                ManifestFinding(
                    rule_id="MANIFEST-006",
                    title="Filesystem access without path restrictions",
                    severity="HIGH",
                    message=f"Tool '{name}' appears to access the filesystem but has no path parameter in its schema.",
                    file=path,
                    tool_name=name,
                )
            ]

        # Path-like params exist but none are required → unrestricted
        if not path_params & required:
            return [
                ManifestFinding(
                    rule_id="MANIFEST-006",
                    title="Filesystem access without path restrictions",
                    severity="HIGH",
                    message=f"Tool '{name}' has path-like parameters that are not required, allowing unrestricted access.",
                    file=path,
                    tool_name=name,
                )
            ]

        return []

    def _check_network(
        self, name: str, schema: dict[str, Any], path: Path
    ) -> list[ManifestFinding]:
        lower = name.lower()
        if not any(hint in lower for hint in self._NETWORK_HINTS):
            return []

        props = schema.get("properties", {})
        if not isinstance(props, dict):
            props = {}

        url_params = {
            k for k in props.keys() if k.lower() in {"url", "endpoint", "address", "link", "uri"}
        }

        # No URL parameter at all → unrestricted
        if not url_params:
            return [
                ManifestFinding(
                    rule_id="MANIFEST-007",
                    title="Network requests without URL allowlist",
                    severity="HIGH",
                    message=f"Tool '{name}' appears to make network requests but has no URL parameter in its schema.",
                    file=path,
                    tool_name=name,
                )
            ]

        # Check whether any URL param has an allowlist (enum or restrictive pattern)
        has_allowlist = False
        for param in url_params:
            param_schema = props.get(param, {})
            if isinstance(param_schema, dict):
                if "enum" in param_schema:
                    has_allowlist = True
                    break
                pattern = param_schema.get("pattern", "")
                if isinstance(pattern, str) and len(pattern) > 5:
                    # A real regex pattern is present – assume restrictive
                    has_allowlist = True
                    break

        if not has_allowlist:
            return [
                ManifestFinding(
                    rule_id="MANIFEST-007",
                    title="Network requests without URL allowlist",
                    severity="HIGH",
                    message=f"Tool '{name}' accepts arbitrary URLs with no domain restriction in its schema.",
                    file=path,
                    tool_name=name,
                )
            ]

        return []

    def _check_prompt_injection(
        self, name: str, description: str, path: Path
    ) -> list[ManifestFinding]:
        for pat in self._PROMPT_INJECTION_PATTERNS:
            if pat.search(description):
                return [
                    ManifestFinding(
                        rule_id="MANIFEST-008",
                        title="Potential prompt injection in description",
                        severity="HIGH",
                        message=f"Tool '{name}' description contains imperative language that could be hijacked for prompt injection.",
                        file=path,
                        tool_name=name,
                    )
                ]
        return []
