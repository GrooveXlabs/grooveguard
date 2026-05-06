"""Click CLI for GrooveGuard."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from grooveguard.manifest import ManifestScanner
from grooveguard.reporters import get_reporter
from grooveguard.rules import build_rules
from grooveguard.scanner import Finding, ScanResult, Scanner
from grooveguard.utils import InvalidTargetError, normalize_path

console = Console()

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

POLICY_RULES = {
    "owasp-llm": ["SEC", "DNG", "VAL", "SSRF"],
    "nist-ai": ["SEC", "DNG", "VAL"],
    "mcp-minimal": ["SEC", "DNG"],
}


def _severity_index(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def _run_scan(
    target: str,
    rules_path: Path | None,
    exclude: tuple[str, ...],
    policy: str | None = None,
) -> ScanResult:
    """Execute a scan and return the result."""
    rules = build_rules(rules_path)

    if policy and policy in POLICY_RULES:
        allowed_prefixes = POLICY_RULES[policy]
        rules = [r for r in rules if any(r.rule_id.startswith(p + "-") for p in allowed_prefixes)]

    scanner = Scanner(rules=rules, exclude_patterns=list(exclude))
    return scanner.scan_target(target)


def _print_summary(result: ScanResult, title: str = "Scan Summary") -> None:
    """Print a rich summary panel."""
    severity_counts: dict[str, int] = {}
    for f in result.findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    summary_lines = [
        f"Files scanned: {result.files_scanned}",
        f"Total findings: {len(result.findings)}",
        f"Duration: {result.duration_ms:.2f} ms",
    ]
    for sev in reversed(SEVERITY_ORDER):
        count = severity_counts.get(sev, 0)
        if count:
            summary_lines.append(f"{sev}: {count}")

    panel = Panel("\n".join(summary_lines), title=title, border_style="cyan")
    console.print(panel)


@click.group()
@click.version_option(version="0.2.0", prog_name="grooveguard")
def main() -> None:
    """GrooveGuard — MCP Server Security Scanner."""


@main.command()
@click.argument("target", type=str)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "sarif", "executive", "remediation"], case_sensitive=False),
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
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER),
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
    min_level = SEVERITY_ORDER.index(fail_on)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Scanning...", total=None)
        result = _run_scan(target, rules_path, exclude)

    reporter_cls = get_reporter(fmt)
    output = reporter_cls.generate(result)
    console.print(output)

    _print_summary(result)

    failed = any(_severity_index(f.severity) >= min_level for f in result.findings)
    if failed:
        sys.exit(1)


@main.command(name="policy-scan")
@click.argument("target", type=str)
@click.option(
    "--policy",
    type=click.Choice(list(POLICY_RULES.keys()), case_sensitive=False),
    default="owasp-llm",
    help="Security policy to apply.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "sarif", "executive", "remediation"], case_sensitive=False),
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
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER),
    default="HIGH",
    help="Minimum severity to exit with code 1.",
)
def policy_scan(
    target: str,
    policy: str,
    fmt: str,
    rules_path: Path | None,
    exclude: tuple[str, ...],
    fail_on: str,
) -> None:
    """Scan TARGET using a named security policy."""
    min_level = SEVERITY_ORDER.index(fail_on)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description=f"Running policy scan ({policy})...", total=None)
        result = _run_scan(target, rules_path, exclude, policy=policy)

    reporter_cls = get_reporter(fmt)
    output = reporter_cls.generate(result)
    console.print(output)

    _print_summary(result, title=f"Policy Scan Summary ({policy})")

    failed = any(_severity_index(f.severity) >= min_level for f in result.findings)
    if failed:
        sys.exit(1)


@main.command()
@click.argument("target", type=str)
@click.option(
    "--exclude",
    multiple=True,
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
def deps(target: str, exclude: tuple[str, ...]) -> None:
    """Scan TARGET for dependency vulnerabilities."""
    path = normalize_path(target)
    dep_files = list(path.rglob("requirements.txt")) + list(path.rglob("package.json"))

    table = Table(title="Dependency Files Found")
    table.add_column("File", style="cyan")
    table.add_column("Type", style="magenta")

    findings: list[dict[str, Any]] = []
    for df in dep_files:
        ftype = "pip" if df.name == "requirements.txt" else "npm"
        table.add_row(str(df), ftype)
        # Simple heuristic: flag http:// or pinned versions without hashes
        content = df.read_text(encoding="utf-8", errors="ignore")
        for lineno, line in enumerate(content.splitlines(), start=1):
            if line.strip().startswith("http://"):
                findings.append({
                    "file": str(df),
                    "line": lineno,
                    "severity": "HIGH",
                    "message": "Dependency fetched over unencrypted HTTP.",
                })
            if "==" in line and "--hash" not in content:
                findings.append({
                    "file": str(df),
                    "line": lineno,
                    "severity": "MEDIUM",
                    "message": "Pinned dependency without hash verification.",
                })

    if not dep_files:
        console.print("[yellow]No dependency files found.[/yellow]")
        return

    console.print(table)

    if findings:
        ftable = Table(title="Dependency Findings")
        ftable.add_column("File", style="cyan")
        ftable.add_column("Line", style="yellow")
        ftable.add_column("Severity", style="red")
        ftable.add_column("Message", style="white")
        for f in findings:
            ftable.add_row(f["file"], str(f["line"]), f["severity"], f["message"])
        console.print(ftable)
    else:
        console.print("[green]No dependency issues detected.[/green]")


@main.command()
@click.argument("target", type=str)
@click.option(
    "--exclude",
    multiple=True,
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
def manifest(target: str, exclude: tuple[str, ...]) -> None:
    """Scan TARGET for MCP manifest / config file issues."""
    path = normalize_path(target)
    scanner = ManifestScanner()

    if path.is_file():
        findings = scanner.scan_manifest(path)
    else:
        findings = scanner.scan_directory(path)

    if not findings:
        console.print("[green]No manifest issues detected.[/green]")
        return

    table = Table(title="Manifest Findings")
    table.add_column("Rule", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("File", style="magenta")
    table.add_column("Tool", style="yellow")
    table.add_column("Message", style="white")

    for f in findings:
        table.add_row(f.rule_id, f.severity, str(f.file), f.tool_name, f.message)

    console.print(table)
    console.print(f"[red]{len(findings)} manifest issue(s) found.[/red]")


@main.command(name="full-scan")
@click.argument("target", type=str)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "markdown", "sarif", "executive", "remediation"], case_sensitive=False),
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
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER),
    default="HIGH",
    help="Minimum severity to exit with code 1.",
)
def full_scan(
    target: str,
    fmt: str,
    rules_path: Path | None,
    exclude: tuple[str, ...],
    fail_on: str,
) -> None:
    """Run all scanners (code, deps, manifest) on TARGET."""
    min_level = SEVERITY_ORDER.index(fail_on)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Running full scan...", total=None)
        result = _run_scan(target, rules_path, exclude)

    reporter_cls = get_reporter(fmt)
    output = reporter_cls.generate(result)
    console.print(output)

    _print_summary(result, title="Full Scan Summary")

    failed = any(_severity_index(f.severity) >= min_level for f in result.findings)
    if failed:
        sys.exit(1)


@main.command()
@click.argument("target", type=str)
@click.option(
    "--interval",
    default=30,
    type=int,
    help="Seconds between scans.",
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
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
def watch(
    target: str,
    interval: int,
    rules_path: Path | None,
    exclude: tuple[str, ...],
) -> None:
    """Continuously monitor TARGET for security issues."""
    console.print(f"[bold green]Starting watch mode (interval={interval}s)...[/bold green]")
    console.print("Press Ctrl+C to stop.")
    try:
        while True:
            result = _run_scan(target, rules_path, exclude)
            _print_summary(result, title=f"Watch Scan @ {time.strftime('%H:%M:%S')}")
            if result.findings:
                console.print("[red]Findings detected![/red]")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Watch mode stopped.[/bold yellow]")


@main.command()
@click.argument("target", type=str)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default="baseline.json",
    help="Baseline file path.",
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
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
def baseline(
    target: str,
    output_path: Path,
    rules_path: Path | None,
    exclude: tuple[str, ...],
) -> None:
    """Generate a baseline scan for TARGET."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Generating baseline...", total=None)
        result = _run_scan(target, rules_path, exclude)

    data = {
        "version": "0.2.0",
        "files_scanned": result.files_scanned,
        "findings": [f.to_dict() for f in result.findings],
    }
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    console.print(f"[green]Baseline saved to {output_path}[/green]")
    _print_summary(result, title="Baseline Summary")


@main.command()
@click.argument("target", type=str)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to baseline JSON file.",
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
    default=["*/.git/*", "*/__pycache__/*", "*/venv/*", "*/tests/*", "*/test_*.py"],
    help="Glob patterns to exclude.",
)
def diff(
    target: str,
    baseline_path: Path,
    rules_path: Path | None,
    exclude: tuple[str, ...],
) -> None:
    """Compare current scan of TARGET against a baseline."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Running diff scan...", total=None)
        result = _run_scan(target, rules_path, exclude)

    baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_findings = {json.dumps(f, sort_keys=True) for f in baseline_data.get("findings", [])}

    new_findings: list[Finding] = []
    for f in result.findings:
        key = json.dumps(f.to_dict(), sort_keys=True)
        if key not in baseline_findings:
            new_findings.append(f)

    if new_findings:
        table = Table(title="New Findings Since Baseline")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("File", style="magenta")
        table.add_column("Line", style="yellow")
        table.add_column("Message", style="white")
        for f in new_findings:
            table.add_row(f.rule_id, f.severity, str(f.file), str(f.line), f.message)
        console.print(table)
        sys.exit(1)
    else:
        console.print("[green]No new findings since baseline.[/green]")


@main.command(name="list-rules")
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
