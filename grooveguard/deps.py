"""Dependency vulnerability scanner using pip-audit."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    tomllib = None  # type: ignore[assignment]

DEPENDENCY_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile.lock",
}


@dataclass
class DependencyFinding:
    """A vulnerability found in a project dependency."""

    rule_id: str
    title: str
    severity: str
    message: str
    file: Path
    package: str
    installed_version: str
    fixed_version: str
    cve_id: str


class DependencyScanner:
    """Scan project dependencies for known CVEs via pip-audit."""

    DEP_FILES = DEPENDENCY_FILES

    def scan_project(self, path: Path) -> list[DependencyFinding]:
        """Scan *path* for vulnerable dependencies.

        Args:
            path: Project directory or a single dependency file.

        Returns:
            List of ``DependencyFinding`` objects.
        """
        dep_files = self._collect_dep_files(path)
        if not dep_files:
            return []

        if not shutil.which("pip-audit"):
            return [
                DependencyFinding(
                    rule_id="DEP-000",
                    title="pip-audit not installed",
                    severity="INFO",
                    message=(
                        "pip-audit is required to scan dependencies. "
                        "Install it with: pip install pip-audit"
                    ),
                    file=path,
                    package="",
                    installed_version="",
                    fixed_version="",
                    cve_id="",
                )
            ]

        findings: list[DependencyFinding] = []
        for dep_file in dep_files:
            raw = self._run_pip_audit(dep_file)
            findings.extend(self._parse_results(raw, dep_file))
        return findings

    def _collect_dep_files(self, path: Path) -> list[Path]:
        """Collect supported dependency files under *path*."""
        files: list[Path] = []
        if path.is_file():
            if path.name in self.DEP_FILES:
                files.append(path)
        elif path.is_dir():
            for name in self.DEP_FILES:
                for candidate in path.rglob(name):
                    files.append(candidate)
        return files

    def _run_pip_audit(self, dep_file: Path) -> list[dict[str, Any]]:
        """Run pip-audit against *dep_file* and return raw dependency data.

        Returns:
            List of dependency dicts from the pip-audit JSON output.
        """
        pip_audit = shutil.which("pip-audit")
        if not pip_audit:
            return []

        cmd: list[str] = [pip_audit, "--format=json"]
        tmp_path: Path | None = None

        if dep_file.name == "requirements.txt":
            cmd.extend(["-r", str(dep_file)])
        elif dep_file.name == "pyproject.toml":
            reqs = self._extract_pyproject_deps(dep_file)
            if not reqs:
                return []
            tmp_path = self._write_temp_requirements(reqs)
            cmd.extend(["-r", str(tmp_path)])
        elif dep_file.name == "poetry.lock":
            reqs = self._extract_poetry_deps(dep_file)
            if not reqs:
                return []
            tmp_path = self._write_temp_requirements(reqs)
            cmd.extend(["-r", str(tmp_path)])
        elif dep_file.name == "Pipfile.lock":
            reqs = self._extract_pipfile_deps(dep_file)
            if not reqs:
                return []
            tmp_path = self._write_temp_requirements(reqs)
            cmd.extend(["-r", str(tmp_path)])
        else:
            return []

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return []
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

        if result.returncode != 0:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        if isinstance(data, dict):
            return data.get("dependencies", [])
        return []

    # ------------------------------------------------------------------
    # File-format helpers
    # ------------------------------------------------------------------

    def _extract_pyproject_deps(self, path: Path) -> list[str] | None:
        """Read ``[project.dependencies]`` from *pyproject.toml*."""
        if tomllib is None:
            return None
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except Exception:
            return None
        deps = data.get("project", {}).get("dependencies", [])
        return [str(d) for d in deps]

    def _extract_poetry_deps(self, path: Path) -> list[str] | None:
        """Extract ``name==version`` lines from a *poetry.lock* file."""
        if tomllib is None:
            return None
        try:
            with path.open("rb") as f:
                data = tomllib.load(f)
        except Exception:
            return None
        packages = data.get("package", [])
        return [f"{pkg['name']}=={pkg['version']}" for pkg in packages]

    def _extract_pipfile_deps(self, path: Path) -> list[str] | None:
        """Extract ``name==version`` lines from a *Pipfile.lock*."""
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None
        default = data.get("default", {})
        return [
            f"{name}=={info['version']}"
            for name, info in default.items()
        ]

    def _write_temp_requirements(self, reqs: list[str]) -> Path:
        """Write *reqs* to a temporary requirements file."""
        fd, name = tempfile.mkstemp(suffix="_requirements.txt")
        with open(fd, "w", encoding="utf-8") as f:
            for line in reqs:
                f.write(f"{line}\n")
        return Path(name)

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    def _parse_results(
        self,
        dependencies: list[dict[str, Any]],
        dep_file: Path,
    ) -> list[DependencyFinding]:
        """Convert pip-audit JSON entries into ``DependencyFinding`` objects."""
        findings: list[DependencyFinding] = []
        for dep in dependencies:
            name = dep.get("name", "unknown")
            version = dep.get("version", "unknown")
            for vuln in dep.get("vulns", []):
                fix_versions = vuln.get("fix_versions", [])
                findings.append(
                    DependencyFinding(
                        rule_id=vuln.get("id", "DEP-UNKNOWN"),
                        title=f"Vulnerability in {name}",
                        severity=self._map_severity(vuln.get("severity")),
                        message=(
                            f"{vuln.get('id', 'UNKNOWN')}: {vuln.get('description', '')} "
                            f"(installed: {version}, fix: {', '.join(fix_versions)})"
                        ),
                        file=dep_file,
                        package=name,
                        installed_version=version,
                        fixed_version=", ".join(fix_versions),
                        cve_id=vuln.get("id", ""),
                    )
                )
        return findings

    @staticmethod
    def _map_severity(severity: str | None) -> str:
        """Map pip-audit severity strings to GrooveGuard severities."""
        mapping = {
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        return mapping.get((severity or "").upper(), "HIGH")
