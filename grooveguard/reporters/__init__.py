"""Output formatters for GrooveGuard."""

from __future__ import annotations

from grooveguard.scanner import ScanResult

from .json_reporter import JSONReporter
from .markdown_reporter import MarkdownReporter
from .sarif_reporter import SARIFReporter

__all__ = ["JSONReporter", "MarkdownReporter", "SARIFReporter", "get_reporter"]


def get_reporter(fmt: str) -> type:
    """Get a reporter class by format name."""
    reporters = {
        "json": JSONReporter,
        "markdown": MarkdownReporter,
        "sarif": SARIFReporter,
    }
    if fmt not in reporters:
        raise ValueError(f"Unknown format: {fmt}")
    return reporters[fmt]
