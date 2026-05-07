"""Configuration system for GrooveGuard.

Supports project-level configuration via `.grooveguard.yml` files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from grooveguard.utils import GrooveGuardError, load_yaml_safe


@dataclass
class RuleConfig:
    """Per-rule configuration."""

    enabled: bool = True
    severity: str | None = None  # Override default severity
    exclude_patterns: list[str] = field(default_factory=list)
    include_patterns: list[str] = field(default_factory=list)


@dataclass
class Config:
    """GrooveGuard project configuration."""

    # Scanning
    target: str = "."
    exclude: list[str] = field(default_factory=lambda: [
        "*/.git/*", "*/__pycache__/*", "*/venv/*", "*/.venv/*",
        "*/node_modules/*", "*/tests/*", "*/test_*.py", "*/build/*",
        "*/dist/*", "*/.tox/*", "*/.eggs/*", "*/.mypy_cache/*",
    ])
    include: list[str] = field(default_factory=list)
    max_file_size_kb: int = 500

    # Severity
    min_severity: str = "LOW"
    fail_on: str = "HIGH"

    # Rules
    rules: dict[str, RuleConfig] = field(default_factory=dict)
    disable_rules: list[str] = field(default_factory=list)
    enable_rules: list[str] = field(default_factory=list)
    only_rules: list[str] = field(default_factory=list)

    # Output
    format: str = "markdown"
    output: str | None = None
    sarif_category: str = "security"

    # Baseline
    baseline: str | None = None

    # Git
    use_git_blame: bool = True

    # Performance
    workers: int = 0  # 0 = auto (cpu_count)

    # Secret scanning
    secret_min_entropy: float = 4.5
    secret_scan_git_history: bool = False

    @classmethod
    def from_file(cls, path: Path) -> Config:
        """Load configuration from a YAML file."""
        data = load_yaml_safe(path)
        if not isinstance(data, dict):
            data = {}
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Build a Config from a dictionary."""
        config = cls()

        # Simple scalar overrides
        config.target = data.get("target", config.target)
        config.min_severity = data.get("min_severity", config.min_severity)
        config.fail_on = data.get("fail_on", config.fail_on)
        config.format = data.get("format", config.format)
        config.output = data.get("output", config.output)
        config.baseline = data.get("baseline", config.baseline)
        config.use_git_blame = data.get("use_git_blame", config.use_git_blame)
        config.workers = data.get("workers", config.workers)
        config.secret_min_entropy = data.get("secret_min_entropy", config.secret_min_entropy)
        config.secret_scan_git_history = data.get("secret_scan_git_history", config.secret_scan_git_history)
        config.max_file_size_kb = data.get("max_file_size_kb", config.max_file_size_kb)

        # Lists
        if "exclude" in data:
            config.exclude = list(data["exclude"])
        if "include" in data:
            config.include = list(data["include"])
        if "disable_rules" in data:
            config.disable_rules = list(data["disable_rules"])
        if "enable_rules" in data:
            config.enable_rules = list(data["enable_rules"])
        if "only_rules" in data:
            config.only_rules = list(data["only_rules"])

        # Per-rule config
        if "rules" in data and isinstance(data["rules"], dict):
            for rule_id, rule_data in data["rules"].items():
                if isinstance(rule_data, dict):
                    config.rules[rule_id] = RuleConfig(
                        enabled=rule_data.get("enabled", True),
                        severity=rule_data.get("severity"),
                        exclude_patterns=list(rule_data.get("exclude_patterns", [])),
                        include_patterns=list(rule_data.get("include_patterns", [])),
                    )
                elif isinstance(rule_data, bool):
                    config.rules[rule_id] = RuleConfig(enabled=rule_data)

        return config

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check whether a rule is enabled by this configuration."""
        if self.only_rules:
            return rule_id in self.only_rules
        if rule_id in self.disable_rules:
            return False
        rule_cfg = self.rules.get(rule_id)
        if rule_cfg is not None:
            return rule_cfg.enabled
        return True

    def get_rule_severity(self, rule_id: str, default: str) -> str:
        """Get the configured severity for a rule, or its default."""
        rule_cfg = self.rules.get(rule_id)
        if rule_cfg and rule_cfg.severity:
            return rule_cfg.severity
        return default

    def should_scan_file(self, path: Path) -> bool:
        """Check whether a file should be scanned given config filters."""
        # Size check
        try:
            size_kb = path.stat().st_size / 1024
            if size_kb > self.max_file_size_kb:
                return False
        except OSError:
            return False

        str_path = str(path.as_posix())
        filename = path.name

        # Include patterns take precedence
        if self.include:
            import fnmatch
            matched = any(
                fnmatch.fnmatch(str_path, pat) or fnmatch.fnmatch(filename, pat)
                for pat in self.include
            )
            if not matched:
                return False

        # Exclude patterns
        import fnmatch
        for pat in self.exclude:
            if fnmatch.fnmatch(str_path, pat) or fnmatch.fnmatch(filename, pat):
                return False

        return True


def find_config(start_path: Path | None = None) -> Path | None:
    """Search upward from *start_path* for `.grooveguard.yml`."""
    if start_path is None:
        start_path = Path.cwd()
    start_path = start_path.resolve()

    # Check for env override first
    env_config = os.environ.get("GROOVEGUARD_CONFIG")
    if env_config:
        p = Path(env_config)
        if p.exists():
            return p

    for path in [start_path, *start_path.parents]:
        candidate = path / ".grooveguard.yml"
        if candidate.exists():
            return candidate
    return None
