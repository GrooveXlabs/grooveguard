"""Click CLI for GrooveGuard Enterprise."""

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

from grooveguard.config import Config, find_config
from grooveguard.manifest import ManifestScanner
from grooveguard.reporters import get_reporter, list_formats
from grooveguard.rules import build_rules
from grooveguard.scanner import Finding, ScanResult, Scanner
from grooveguard.utils import InvalidTargetError, normalize_path

console = Console()

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

POLICY_RULES = {
    "owasp-llm": ["SEC", "DNG", "VAL", "SSRF", "INJ", "CRY", "NET", "XML", "LOG"],
    "nist-ai": ["SEC", "DNG", "VAL", "INJ", "CRY"],
    "mcp-minimal": ["SEC", "DNG"],
    "owasp-top10": ["SEC", "DNG", "INJ", "CRY", "SSRF", "NET", "XML", "LOG", "VAL"],
}


def _severity_index(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def _load_config(rules_path: Path | None, target: str) -> Config:
    """Load configuration from file or defaults."""
    config_path = find_config(Path(target))
    if config_path:
        return Config.from_file(config_path)
    return Config()


def _run_scan(
    target: str,
    rules_path: Path | None,
    exclude: tuple[str, ...],
    policy: str | None = None,
    config: Config | None = None,
) -> ScanResult:
    """Execute a scan and return the result."""
    cfg = config or Config()
    rules = build_rules(rules_path, config=cfg)

    if policy and policy in POLICY_RULES:
        allowed_prefixes = POLICY_RULES[policy]
        rules = [r for r in rules if any(r.rule_id.startswith(p + "-") for p in allowed_prefixes)]

    # Merge CLI excludes with config excludes
    all_excludes = list(cfg.exclude)
    if exclude:
        all_excludes.extend(exclude)

    scanner = Scanner(
        rules=rules,
        exclude_patterns=all_excludes,
        workers=cfg.workers,
        use_git_blame=cfg.use_git_blame,
        max_file_size_kb=cfg.max_file_size_kb,
    )
    return scanner.scan_target(target)


def _print_summary(result: ScanResult, title: str = "Scan Summary") -> None:
    """Print a rich summary panel."""
    severity_counts = result.severity_counts

    summary_lines = [
        f"Files scanned: {result.files_scanned}",
        f"Files skipped: {result.files_skipped}",
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
@click.version_option(version="1.0.0", prog_name="grooveguard")
def main() -> None:
    """GrooveGuard Enterprise — Python Security Scanner."""


@main.command()
@click.argument("target", type=str)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(list_formats(), case_sensitive=False),
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
    default=[],
    help="Glob patterns to exclude.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER),
    default="HIGH",
    help="Minimum severity to exit with code 1.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    help="Write output to file.",
)
@click.option(
    "--workers",
    type=int,
    default=0,
    help="Number of parallel workers (0=auto).",
)
@click.option(
    "--no-git-blame",
    is_flag=True,
    help="Disable git blame enrichment.",
)
def scan(
    target: str,
    fmt: str,
    rules_path: Path | None,
    exclude: tuple[str, ...],
    fail_on: str,
    output_path: Path | None,
    workers: int,
    no_git_blame: bool,
) -> None:
    """Scan TARGET file or directory for security issues."""
    min_level = SEVERITY_ORDER.index(fail_on)
    config = _load_config(rules_path, target)
    if workers > 0:
        config.workers = workers
    if no_git_blame:
        config.use_git_blame = False

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Scanning...", total=None)
        result = _run_scan(target, rules_path, exclude, config=config)

    reporter_cls = get_reporter(fmt)
    output = reporter_cls.generate(result)

    if output_path:
        output_path.write_text(output, encoding="utf-8")
        console.print(f"[green]Report saved to {output_path}[/green]")
    else:
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
    default="owasp-top10",
    help="Security policy to apply.",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(list_formats(), case_sensitive=False),
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
    default=[],
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
    config = _load_config(rules_path, target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description=f"Running policy scan ({policy})...", total=None)
        result = _run_scan(target, rules_path, exclude, policy=policy, config=config)

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
    default=[],
    help="Glob patterns to exclude.",
)
def deps(target: str, exclude: tuple[str, ...]) -> None:
    """Scan TARGET for dependency vulnerabilities."""
    from grooveguard.deps import DependencyScanner

    path = normalize_path(target)
    dep_files = list(path.rglob("requirements.txt")) + list(path.rglob("package.json"))

    table = Table(title="Dependency Files Found")
    table.add_column("File", style="cyan")
    table.add_column("Type", style="magenta")

    findings: list[dict[str, Any]] = []
    for df in dep_files:
        ftype = "pip" if df.name == "requirements.txt" else "npm"
        table.add_row(str(df), ftype)
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
    default=[],
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
    type=click.Choice(list_formats(), case_sensitive=False),
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
    default=[],
    help="Glob patterns to exclude.",
)
@click.option(
    "--fail-on",
    type=click.Choice(SEVERITY_ORDER),
    default="HIGH",
    help="Minimum severity to exit with code 1.",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    help="Write output to file.",
)
def full_scan(
    target: str,
    fmt: str,
    rules_path: Path | None,
    exclude: tuple[str, ...],
    fail_on: str,
    output_path: Path | None,
) -> None:
    """Run all scanners (code, deps, manifest) on TARGET."""
    min_level = SEVERITY_ORDER.index(fail_on)
    config = _load_config(rules_path, target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Running full scan...", total=None)
        result = _run_scan(target, rules_path, exclude, config=config)

    reporter_cls = get_reporter(fmt)
    output = reporter_cls.generate(result)

    if output_path:
        output_path.write_text(output, encoding="utf-8")
    else:
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
    default=[],
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
    default=[],
    help="Glob patterns to exclude.",
)
def baseline(
    target: str,
    output_path: Path,
    rules_path: Path | None,
    exclude: tuple[str, ...],
) -> None:
    """Generate a baseline scan for TARGET."""
    config = _load_config(rules_path, target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Generating baseline...", total=None)
        result = _run_scan(target, rules_path, exclude, config=config)

    data = {
        "version": "1.0.0",
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
    default=[],
    help="Glob patterns to exclude.",
)
def diff(
    target: str,
    baseline_path: Path,
    rules_path: Path | None,
    exclude: tuple[str, ...],
) -> None:
    """Compare current scan of TARGET against a baseline."""
    config = _load_config(rules_path, target)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Running diff scan...", total=None)
        result = _run_scan(target, rules_path, exclude, config=config)

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
    table.add_column("CWE", style="yellow")

    for rule in rules:
        cwe = f"{rule.cwe_id} ({rule.cwe_name})" if rule.cwe_id else "—"
        table.add_row(rule.rule_id, rule.title, rule.severity, cwe)

    console.print(table)


@main.command()
@click.argument("target", type=str, default=".")
def init(target: str) -> None:
    """Initialize a GrooveGuard configuration file in TARGET."""
    path = Path(target) / ".grooveguard.yml"
    if path.exists():
        console.print(f"[yellow]{path} already exists.[/yellow]")
        return

    default_config = """# GrooveGuard Configuration
# Documentation: https://github.com/GrooveXlabs/grooveguard

# Target directory or file to scan
target: "."

# Glob patterns to exclude from scanning
exclude:
  - "*/.git/*"
  - "*/__pycache__/*"
  - "*/venv/*"
  - "*/.venv/*"
  - "*/node_modules/*"
  - "*/tests/*"
  - "*/test_*.py"

# Minimum severity to report
min_severity: "LOW"

# Minimum severity to fail CI (exit code 1)
fail_on: "HIGH"

# Output format: markdown, json, sarif, html, executive, remediation
format: "markdown"

# Number of parallel workers (0 = auto)
workers: 0

# Enable git blame enrichment
use_git_blame: true

# Secret scanning options
secret_min_entropy: 4.5

# Per-rule configuration
rules:
  SEC-004:
    enabled: true
    severity: "MEDIUM"
  DNG-010:
    enabled: true
"""
    path.write_text(default_config, encoding="utf-8")
    console.print(f"[green]Created {path}[/green]")


if __name__ == "__main__":
    main()
