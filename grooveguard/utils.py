"""Shared helpers for GrooveGuard."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class GrooveGuardError(Exception):
    """Base exception for GrooveGuard."""


class InvalidTargetError(GrooveGuardError):
    """Raised when a scan target is invalid or unsafe."""


def normalize_path(target: str) -> Path:
    """Resolve and validate a filesystem path.

    Args:
        target: Raw path string.

    Returns:
        Absolute, resolved Path.

    Raises:
        InvalidTargetError: If the path does not exist or is unreadable.
    """
    path = Path(target).resolve()
    if not path.exists():
        raise InvalidTargetError(f"Path does not exist: {path}")
    return path


def is_safe_url(url: str) -> bool:
    """Check whether a URL points to a public, safe endpoint.

    Blocks private IPs, localhost, and common metadata endpoints.

    Args:
        url: The URL to validate.

    Returns:
        True if the URL appears safe, False otherwise.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False

    blocked = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "169.254.169.254",  # AWS metadata
    }
    if hostname in blocked:
        return False
    if hostname.startswith("192.168.") or hostname.startswith("10."):
        return False
    if hostname.startswith("172."):
        parts = hostname.split(".")
        if len(parts) >= 2 and 16 <= int(parts[1]) <= 31:
            return False
    return True


def calculate_file_hash(path: Path) -> str:
    """Calculate SHA-256 hash of a file's contents.

    Args:
        path: Path to the file.

    Returns:
        Hex digest string.
    """
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def has_ignore_comment(line: str, rule_id: str | None = None) -> bool:
    """Check whether a line contains a GrooveGuard ignore comment.

    Supports:
        # grooveguard: ignore
        # grooveguard: ignore=RULE-001

    Args:
        line: Source code line.
        rule_id: Optional specific rule ID to check.

    Returns:
        True if the line should be ignored for the given rule.
    """
    match = re.search(r"#\s*grooveguard:\s*ignore(?:=([A-Z0-9\-]+))?", line, re.IGNORECASE)
    if not match:
        return False
    ignored_rule = match.group(1)
    if rule_id and ignored_rule:
        return ignored_rule == rule_id
    return True


def load_yaml_safe(path: Path) -> Any:
    """Load YAML without executing arbitrary code.

    Args:
        path: Path to YAML file.

    Returns:
        Parsed YAML content.

    Raises:
        GrooveGuardError: If parsing fails.
    """
    import yaml

    try:
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise GrooveGuardError(f"Failed to parse YAML {path}: {exc}") from exc
