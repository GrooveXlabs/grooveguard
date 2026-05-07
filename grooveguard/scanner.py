"""Main scanner engine for GrooveGuard."""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from grooveguard.utils import calculate_file_hash, has_ignore_comment, normalize_path


@dataclass(frozen=True)
class Finding:
    """A single security finding."""

    rule_id: str
    title: str
    severity: str
    message: str
    file: Path
    line: int
    column: int
    snippet: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    owasp: str = ""
    remediation: str = ""
    git_author: str = ""
    git_date: str = ""
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "file": str(self.file),
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp": self.owasp,
            "remediation": self.remediation,
            "git_author": self.git_author,
            "git_date": self.git_date,
            "fingerprint": self.fingerprint,
        }

    def compute_fingerprint(self) -> str:
        """Compute a stable fingerprint for deduplication."""
        content = f"{self.rule_id}:{self.file}:{self.line}:{self.column}:{self.snippet}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    """Aggregated scan results."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: float = 0.0
    files_skipped: int = 0

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class Rule:
    """Base class for security rules."""

    rule_id: str = "RULE-000"
    title: str = "Base Rule"
    severity: str = "INFO"
    cwe_id: str = ""
    cwe_name: str = ""
    owasp: str = ""
    remediation: str = ""

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        """Yield findings for the given AST and source lines."""
        yield from ()

    def make_finding(
        self,
        message: str,
        path: Path,
        line: int,
        column: int,
        snippet: str = "",
    ) -> Finding:
        """Helper to create a Finding with rule metadata pre-filled."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            message=message,
            file=path,
            line=line,
            column=column,
            snippet=snippet,
            cwe_id=self.cwe_id,
            cwe_name=self.cwe_name,
            owasp=self.owasp,
            remediation=self.remediation,
        )


def _scan_file_worker(
    args: tuple[str, list[type[Rule]], list[str]]
) -> tuple[list[dict[str, Any]], bool]:
    """Worker function for multiprocessing file scanning.

    Must be picklable — uses plain types only.
    """
    file_path_str, rules_data, exclude_patterns = args
    path = Path(file_path_str)

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], False

    # Check exclusion
    str_path = str(path.as_posix())
    filename = path.name
    for pat in exclude_patterns:
        if fnmatch.fnmatch(str_path, pat) or fnmatch.fnmatch(filename, pat):
            return [], False

    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [], True

    findings: list[dict[str, Any]] = []
    # Reconstruct rule instances from class data
    # This is a simplified version - full reconstruction needs rule registry
    return findings, True


class Scanner:
    """Orchestrates scanning of Python code."""

    def __init__(
        self,
        rules: list[Rule],
        exclude_patterns: list[str] | None = None,
        workers: int = 0,
        use_git_blame: bool = False,
        max_file_size_kb: int = 500,
    ):
        self.rules = rules
        self.exclude_patterns = (
            exclude_patterns
            if exclude_patterns is not None
            else [
                "*/.git/*", "*/__pycache__/*", "*/venv/*", "*/.venv/*",
                "*/tests/*", "*/test_*.py", "*/node_modules/*",
            ]
        )
        self.workers = workers if workers > 0 else max(1, multiprocessing.cpu_count() - 1)
        self.use_git_blame = use_git_blame
        self.max_file_size_kb = max_file_size_kb
        self._git_cache: dict[str, tuple[str, str]] = {}

    def scan_target(self, target: str | Path) -> ScanResult:
        """Scan a single file or directory."""
        start = time.perf_counter()
        path = normalize_path(str(target))
        findings: list[Finding] = []
        files_scanned = 0
        files_skipped = 0

        if path.is_file():
            file_findings = self._scan_file(path)
            findings.extend(file_findings)
            files_scanned = 1
        elif path.is_dir():
            py_files = list(path.rglob("*.py"))
            if self.workers > 1 and len(py_files) > 10:
                findings, files_scanned, files_skipped = self._scan_parallel(py_files)
            else:
                for py_file in py_files:
                    if self._is_excluded(py_file):
                        files_skipped += 1
                        continue
                    if not self._check_size(py_file):
                        files_skipped += 1
                        continue
                    findings.extend(self._scan_file(py_file))
                    files_scanned += 1

        duration = (time.perf_counter() - start) * 1000

        # Enrich with git blame if enabled
        if self.use_git_blame:
            self._enrich_git_blame(findings)

        # Compute fingerprints
        for f in findings:
            object.__setattr__(f, "fingerprint", f.compute_fingerprint())

        return ScanResult(
            findings=findings,
            files_scanned=files_scanned,
            duration_ms=duration,
            files_skipped=files_skipped,
        )

    def _scan_parallel(
        self, files: list[Path]
    ) -> tuple[list[Finding], int, int]:
        """Scan files using a thread pool (faster than process for AST parsing)."""
        findings: list[Finding] = []
        scanned = 0
        skipped = 0

        valid_files: list[Path] = []
        for f in files:
            if self._is_excluded(f):
                skipped += 1
                continue
            if not self._check_size(f):
                skipped += 1
                continue
            valid_files.append(f)

        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            results = executor.map(self._scan_file, valid_files)
            for file_findings in results:
                findings.extend(file_findings)
                scanned += 1

        return findings, scanned, skipped

    def _is_excluded(self, path: Path) -> bool:
        str_path = str(path.as_posix())
        filename = path.name
        for pat in self.exclude_patterns:
            if fnmatch.fnmatch(str_path, pat) or fnmatch.fnmatch(filename, pat):
                return True
        return False

    def _check_size(self, path: Path) -> bool:
        try:
            return path.stat().st_size / 1024 <= self.max_file_size_kb
        except OSError:
            return False

    def _scan_file(self, path: Path) -> list[Finding]:
        """Scan a single Python file."""
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []

        lines = source.splitlines()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        findings: list[Finding] = []
        for rule in self.rules:
            try:
                for finding in rule.check(tree, lines, path):
                    if finding.line > 0 and finding.line <= len(lines):
                        if has_ignore_comment(lines[finding.line - 1], finding.rule_id):
                            continue
                    findings.append(finding)
            except Exception:
                # Never let a single rule crash the scan
                continue
        return findings

    def _enrich_git_blame(self, findings: list[Finding]) -> None:
        """Add git blame info to findings."""
        import subprocess

        files: dict[Path, set[int]] = {}
        for f in findings:
            files.setdefault(f.file, set()).add(f.line)

        for file_path, line_numbers in files.items():
            for line in line_numbers:
                key = f"{file_path}:{line}"
                if key in self._git_cache:
                    author, date = self._git_cache[key]
                else:
                    author, date = self._git_blame_line(file_path, line)
                    self._git_cache[key] = (author, date)

                for f in findings:
                    if f.file == file_path and f.line == line:
                        object.__setattr__(f, "git_author", author)
                        object.__setattr__(f, "git_date", date)

    @staticmethod
    def _git_blame_line(path: Path, line: int) -> tuple[str, str]:
        """Get git blame info for a specific line."""
        import subprocess

        try:
            result = subprocess.run(
                ["git", "blame", "-L", f"{line},{line}", "--porcelain", str(path)],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=path.parent if path.is_file() else str(path),
            )
            if result.returncode != 0:
                return ("", "")
            author = ""
            date = ""
            for ln in result.stdout.splitlines():
                if ln.startswith("author ") and not ln.startswith("author-mail"):
                    author = ln[7:]
                elif ln.startswith("author-time "):
                    import datetime
                    ts = int(ln[12:])
                    date = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
                        "%Y-%m-%d"
                    )
            return (author, date)
        except Exception:
            return ("", "")
