"""Output formatters for GrooveGuard."""

from __future__ import annotations

from grooveguard.scanner import ScanResult

from .executive_reporter import ExecutiveReporter
from .html_reporter import HTMLReporter
from .json_reporter import JSONReporter
from .markdown_reporter import MarkdownReporter
from .remediation_reporter import RemediationReporter
from .sarif_reporter import SARIFReporter

__all__ = [
    "ExecutiveReporter",
    "HTMLReporter",
    "JSONReporter",
    "MarkdownReporter",
    "RemediationReporter",
    "SARIFReporter",
    "get_reporter",
]


REPORTERS: dict[str, type] = {
    "json": JSONReporter,
    "markdown": MarkdownReporter,
    "sarif": SARIFReporter,
    "executive": ExecutiveReporter,
    "remediation": RemediationReporter,
    "html": HTMLReporter,
}


def get_reporter(fmt: str) -> type:
    """Get a reporter class by format name."""
    fmt_lower = fmt.lower()
    if fmt_lower not in REPORTERS:
        raise ValueError(f"Unknown format: {fmt}. Supported: {', '.join(REPORTERS.keys())}")
    return REPORTERS[fmt_lower]


def list_formats() -> list[str]:
    """Return list of supported output formats."""
    return list(REPORTERS.keys())
