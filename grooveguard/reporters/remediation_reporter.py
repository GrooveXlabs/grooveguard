"""Remediation reporter with step-by-step fixes."""

from __future__ import annotations

from collections import defaultdict

from grooveguard.scanner import Finding, ScanResult


class RemediationReporter:
    """Generate prioritized remediation guides with before/after code examples."""

    _EFFORT_MAP = {
        "SEC-001": "Quick",
        "SEC-002": "Quick",
        "SEC-003": "Quick",
        "DNG-001": "Medium",
        "DNG-002": "Medium",
        "DNG-003": "Hard",
        "VAL-001": "Medium",
        "SSRF-001": "Medium",
    }

    _REMEDIATIONS = {
        "SEC-001": {
            "steps": [
                "Identify all locations where API keys are hardcoded.",
                "Remove the hardcoded value from source code.",
                "Load the key from an environment variable or secrets manager at runtime.",
                "Rotate the exposed key in the upstream provider console.",
            ],
            "before": "api_key = 'sk-abcdefghijklmnopqrstuvwxyz123456'",
            "after": "import os\n\napi_key = os.getenv('API_KEY')\nif not api_key:\n    raise RuntimeError('API_KEY not set')",
        },
        "SEC-002": {
            "steps": [
                "Replace the hardcoded token with a runtime configuration source.",
                "Use a secrets vault (e.g., AWS Secrets Manager, HashiCorp Vault) for production.",
                "Revoke the exposed token and generate a new one.",
            ],
            "before": "auth_token = 'supersecrettoken123'",
            "after": "import os\n\nauth_token = os.getenv('AUTH_TOKEN')\nif not auth_token:\n    raise RuntimeError('AUTH_TOKEN not set')",
        },
        "SEC-003": {
            "steps": [
                "Remove plain-text passwords from code and configuration files.",
                "Store credentials in a dedicated secrets manager or use environment variables.",
                "Force a password reset for any affected accounts.",
            ],
            "before": "password = 'hunter2'",
            "after": "import os\n\npassword = os.getenv('SERVICE_PASSWORD')\nif not password:\n    raise RuntimeError('SERVICE_PASSWORD not set')",
        },
        "DNG-001": {
            "steps": [
                "Avoid shelling out to the OS from application code.",
                "If unavoidable, use parameterized APIs and strict allow-lists.",
                "Require explicit administrator approval for any shell execution tool.",
            ],
            "before": "import os\nos.system(user_input)",
            "after": "import subprocess\n\nALLOWED = {'ls', 'cat'}\nif command not in ALLOWED:\n    raise PermissionError('Command not allowed')\nsubprocess.run([command, arg], capture_output=True, check=True)",
        },
        "DNG-002": {
            "steps": [
                "Validate all file paths before opening them for writing.",
                "Use a sandboxed directory and reject parent-directory references (..).",
                "Log all write operations for audit purposes.",
            ],
            "before": "open(filename, 'w')",
            "after": "from pathlib import Path\n\nSAFE_DIR = Path('/var/safe/uploads')\npath = SAFE_DIR / Path(filename).name\nif not path.resolve().is_relative_to(SAFE_DIR):\n    raise ValueError('Invalid path')\nwith open(path, 'w') as f:\n    f.write(data)",
        },
        "DNG-003": {
            "steps": [
                "Rename tools to remove dangerous-sounding capability names.",
                "Implement least-privilege access controls around the tool.",
                "Add mandatory human-in-the-loop approval for destructive operations.",
            ],
            "before": "def run_command(cmd):\n    ...",
            "after": "def execute_approved_command(cmd: str) -> str:\n    if not _is_approved(cmd):\n        raise PermissionError('Command not approved')\n    ...",
        },
        "VAL-001": {
            "steps": [
                "Add type and length checks for every function parameter.",
                "Reject unexpected types early and raise descriptive errors.",
                "Consider using a validation library such as Pydantic.",
            ],
            "before": "def fetch_url(url):\n    import requests\n    requests.get(url)",
            "after": "from urllib.parse import urlparse\n\ndef fetch_url(url: str) -> None:\n    if not isinstance(url, str) or not url.startswith('https://'):\n        raise ValueError('Invalid URL')\n    import requests\n    requests.get(url, timeout=30)",
        },
        "SSRF-001": {
            "steps": [
                "Validate URLs against an explicit allow-list of trusted domains.",
                "Block private IP ranges, localhost, and link-local addresses.",
                "Use a dedicated SSRF-safe HTTP client wrapper if available.",
            ],
            "before": "def fetch(url):\n    import requests\n    requests.get(url)",
            "after": "from urllib.parse import urlparse\n\nALLOWED_HOSTS = {'api.example.com'}\n\ndef fetch(url: str) -> None:\n    parsed = urlparse(url)\n    if parsed.hostname not in ALLOWED_HOSTS:\n        raise ValueError('Host not allowed')\n    import requests\n    requests.get(url, timeout=30)",
        },
    }

    @staticmethod
    def generate(result: ScanResult) -> str:
        """Return a remediation guide string for the scan result."""
        lines: list[str] = [
            "# Remediation Guide",
            "",
            "## Summary",
            "",
            f"- **Total findings:** {len(result.findings)}",
            f"- **Files scanned:** {result.files_scanned}",
            "",
        ]

        if not result.findings:
            lines.append("*No findings require remediation.*")
            return "\n".join(lines)

        # Group and sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.get(f.severity, 5),
        )

        # Group by rule_id
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for f in sorted_findings:
            grouped[f.rule_id].append(f)

        for rule_id in grouped:
            findings = grouped[rule_id]
            first = findings[0]
            effort = RemediationReporter._EFFORT_MAP.get(rule_id, "Medium")
            remediation = RemediationReporter._REMEDIATIONS.get(rule_id, {})

            lines.append(f"## {rule_id}: {first.title}")
            lines.append("")
            lines.append(f"**Severity:** {first.severity}")
            lines.append(f"**Occurrences:** {len(findings)}")
            lines.append(f"**Estimated Effort:** {effort}")
            lines.append("")
            lines.append("### Step-by-step Fix")
            lines.append("")

            if remediation:
                for i, step in enumerate(remediation.get("steps", []), start=1):
                    lines.append(f"{i}. {step}")
                lines.append("")

                before = remediation.get("before", "")
                after = remediation.get("after", "")
                if before:
                    lines.append("### Before")
                    lines.append("```python")
                    lines.append(before)
                    lines.append("```")
                    lines.append("")
                if after:
                    lines.append("### After")
                    lines.append("```python")
                    lines.append(after)
                    lines.append("```")
                    lines.append("")
            else:
                lines.append("1. Review the flagged code manually.")
                lines.append("2. Apply defensive security best practices for this pattern.")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)
