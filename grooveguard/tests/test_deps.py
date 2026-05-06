"""Tests for the dependency vulnerability scanner."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from grooveguard.deps import DependencyFinding, DependencyScanner


class FakeCompletedProcess:
    """Minimal stand-in for ``subprocess.CompletedProcess``."""

    def __init__(self, stdout: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode


class TestDependencyScanner:
    # ------------------------------------------------------------------
    # 1. No dependency files found
    # ------------------------------------------------------------------
    def test_no_dependency_files_found(self, tmp_path: Path) -> None:
        scanner = DependencyScanner()
        findings = scanner.scan_project(tmp_path)
        assert findings == []

    # ------------------------------------------------------------------
    # 2. requirements.txt with a vulnerable package
    # ------------------------------------------------------------------
    def test_requirements_txt_with_vulnerability(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.25.0\n")

        def mock_run(*args: Any, **kwargs: Any) -> FakeCompletedProcess:
            data = {
                "dependencies": [
                    {
                        "name": "requests",
                        "version": "2.25.0",
                        "vulns": [
                            {
                                "id": "CVE-2023-1234",
                                "fix_versions": ["2.31.0"],
                                "description": "SSRF vulnerability",
                                "severity": "HIGH",
                            }
                        ],
                    }
                ]
            }
            return FakeCompletedProcess(stdout=json.dumps(data))

        monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/pip-audit")
        monkeypatch.setattr(subprocess, "run", mock_run)

        scanner = DependencyScanner()
        findings = scanner.scan_project(tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "CVE-2023-1234"
        assert f.title == "Vulnerability in requests"
        assert f.severity == "HIGH"
        assert f.package == "requests"
        assert f.installed_version == "2.25.0"
        assert f.fixed_version == "2.31.0"
        assert f.cve_id == "CVE-2023-1234"
        assert f.file.name == "requirements.txt"

    # ------------------------------------------------------------------
    # 3. pyproject.toml with a vulnerable package
    # ------------------------------------------------------------------
    def test_pyproject_toml_with_vulnerability(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[project]\nname = "test"\ndependencies = ["requests>=2.25.0"]\n'
        )

        def mock_run(*args: Any, **kwargs: Any) -> FakeCompletedProcess:
            cmd = args[0]
            assert "-r" in cmd
            idx = cmd.index("-r")
            tmp_file = Path(cmd[idx + 1])
            assert tmp_file.exists()
            content = tmp_file.read_text()
            assert "requests>=2.25.0" in content

            data = {
                "dependencies": [
                    {
                        "name": "requests",
                        "version": "2.25.0",
                        "vulns": [
                            {
                                "id": "CVE-2023-5678",
                                "fix_versions": ["2.31.0"],
                                "description": "Buffer overflow",
                                "severity": "CRITICAL",
                            }
                        ],
                    }
                ]
            }
            return FakeCompletedProcess(stdout=json.dumps(data))

        monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/pip-audit")
        monkeypatch.setattr(subprocess, "run", mock_run)

        scanner = DependencyScanner()
        findings = scanner.scan_project(tmp_path)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "CVE-2023-5678"
        assert f.severity == "CRITICAL"
        assert f.package == "requests"

    # ------------------------------------------------------------------
    # 4. pip-audit not installed -> fallback warning
    # ------------------------------------------------------------------
    def test_pip_audit_not_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.25.0\n")
        monkeypatch.setattr(shutil, "which", lambda x: None)

        scanner = DependencyScanner()
        findings = scanner.scan_project(tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "DEP-000"
        assert findings[0].title == "pip-audit not installed"
        assert findings[0].severity == "INFO"

    # ------------------------------------------------------------------
    # 5. Clean dependency file (no vulnerabilities)
    # ------------------------------------------------------------------
    def test_clean_dependency_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\n")

        def mock_run(*args: Any, **kwargs: Any) -> FakeCompletedProcess:
            data = {
                "dependencies": [
                    {
                        "name": "requests",
                        "version": "2.31.0",
                        "vulns": [],
                    }
                ]
            }
            return FakeCompletedProcess(stdout=json.dumps(data))

        monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/pip-audit")
        monkeypatch.setattr(subprocess, "run", mock_run)

        scanner = DependencyScanner()
        findings = scanner.scan_project(tmp_path)
        assert findings == []

    # ------------------------------------------------------------------
    # 6. Invalid JSON from pip-audit (error handling)
    # ------------------------------------------------------------------
    def test_invalid_json_from_pip_audit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.25.0\n")

        def mock_run(*args: Any, **kwargs: Any) -> FakeCompletedProcess:
            return FakeCompletedProcess(stdout="not valid json", returncode=0)

        monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/pip-audit")
        monkeypatch.setattr(subprocess, "run", mock_run)

        scanner = DependencyScanner()
        findings = scanner.scan_project(tmp_path)
        assert findings == []

    # ------------------------------------------------------------------
    # 7. Subprocess non-zero exit code (extra error handling)
    # ------------------------------------------------------------------
    def test_subprocess_nonzero_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.25.0\n")

        def mock_run(*args: Any, **kwargs: Any) -> FakeCompletedProcess:
            return FakeCompletedProcess(stdout="", returncode=1)

        monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/pip-audit")
        monkeypatch.setattr(subprocess, "run", mock_run)

        scanner = DependencyScanner()
        findings = scanner.scan_project(tmp_path)
        assert findings == []
