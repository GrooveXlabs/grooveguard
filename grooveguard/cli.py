"""Click CLI for GrooveGuard."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from grooveguard.reporters import get_reporter
from grooveguard.rules import build_rules
from grooveguard.scanner import Scanner

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="grooveguard")
def main() -> None:
    """GrooveGuard — MCP Server Security Scanner."""


@main.command()
@click.argument("target", type=str)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "sarif"], case_sensitive=False),
    default="markdown",
    help="Output format.",
)
@click.option(
    "--rules",
    "rules_path",
    type=click.Path(exists=True, path_type=Path),
    help="Custom YAML rule file.",
)
@click.option(
    "--exclude",
    multiple=True,
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*"],
    help="Glob patterns to exclude.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    default="HIGH",
    help="Minimum severity to exit with code 1.",
)
def scan(
    target: str,
    fmt: str,
    rules_path: Path | None,
    exclude: tuple[str, ...],
    fail_on: str,
) -> None:
    """Scan TARGET file or directory for MCP security issues."""
    severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_level = severity_order.index(fail_on)

    rules = build_rules(rules_path)
    scanner = Scanner(rules=rules, exclude_patterns=list(exclude))
    result = scanner.scan_target(target)

    reporter_cls = get_reporter(fmt)
    output = reporter_cls.generate(result)
    console.print(output)

    failed = any(
        severity_order.index(f.severity) >= min_level for f in result.findings
    )
    if failed:
        sys.exit(1)


@main.command()
def list_rules() -> None:
    """List built-in security rules."""
    rules = build_rules()
    table = Table(title="Built-in Security Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="magenta")
    table.add_column("Severity", style="red")

    for rule in rules:
        table.add_row(rule.rule_id, rule.title, rule.severity)

    console.print(table)


if __name__ == "__main__":
    main()
