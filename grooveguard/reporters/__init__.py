"""Output formatters for GrooveGuard."""

from __future__ import annotations

from grooveguard.scanner import ScanResult

from .executive_reporter import ExecutiveReporter
from .json_reporter import JSONReporter
from .markdown_reporter import MarkdownReporter
from .remediation_reporter import RemediationReporter
from .sarif_reporter import SARIFReporter

__all__ = [
    "ExecutiveReporter",
    "JSONReporter",
    "MarkdownReporter",
    "RemediationReporter",
    "SARIFReporter",
    "get_reporter",
]


def get_reporter(fmt: str) -> type:
    """Get a reporter class by format name."""
    reporters = {
        "json": JSONReporter,
        "markdown": MarkdownReporter,
        "sarif": SARIFReporter,
        "executive": ExecutiveReporter,
        "remediation": RemediationReporter,
    }
    if fmt not in reporters:
        raise ValueError(f"Unknown format: {fmt}")
    return reporters[fmt]
