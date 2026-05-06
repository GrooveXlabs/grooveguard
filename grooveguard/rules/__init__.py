"""Security rule definitions for GrooveGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from grooveguard.scanner import Rule
from grooveguard.utils import load_yaml_safe

from .dangerous import DangerousToolRule, FileWriteRule, ShellExecRule
from .secrets import ApiKeyRule, HardcodedPasswordRule, SecretTokenRule
from .ssrf import UnvalidatedUrlFetchRule
from .validation import MissingValidationRule

__all__ = [
    "ApiKeyRule",
    "DangerousToolRule",
    "FileWriteRule",
    "HardcodedPasswordRule",
    "MissingValidationRule",
    "SecretTokenRule",
    "ShellExecRule",
    "UnvalidatedUrlFetchRule",
    "load_rules_from_yaml",
    "build_rules",
]


def load_rules_from_yaml(path: Path) -> list[dict[str, Any]]:
    """Load rule definitions from a YAML file.

    Args:
        path: Path to YAML file.

    Returns:
        List of rule dictionaries.
    """
    data = load_yaml_safe(path)
    if isinstance(data, dict) and "rules" in data:
        return data["rules"]
    if isinstance(data, list):
        return data
    return []


def build_rules(yaml_path: Path | None = None) -> list[Rule]:
    """Build the default rule set, optionally extended by YAML.

    Args:
        yaml_path: Optional custom YAML rule file.

    Returns:
        List of Rule instances.
    """
    rules: list[Rule] = [
        ApiKeyRule(),
        SecretTokenRule(),
        HardcodedPasswordRule(),
        ShellExecRule(),
        FileWriteRule(),
        DangerousToolRule(),
        MissingValidationRule(),
        UnvalidatedUrlFetchRule(),
    ]

    if yaml_path and yaml_path.exists():
        raw_rules = load_rules_from_yaml(yaml_path)
        for raw in raw_rules:
            rule = _make_rule_from_dict(raw)
            if rule:
                rules.append(rule)

    return rules


def _make_rule_from_dict(raw: dict[str, Any]) -> Rule | None:
    """Create a Rule from a YAML dictionary.

    Supports pattern-based rules using simple string/regex matching.
    """
    import ast
    import re

    from grooveguard.scanner import Finding

    rule_id = raw.get("id", "CUSTOM-000")
    title = raw.get("title", "Custom Rule")
    severity = raw.get("severity", "MEDIUM")
    pattern = raw.get("pattern")
    message_template = raw.get("message", "Suspicious code pattern detected.")

    if not pattern:
        return None

    compiled = re.compile(pattern)

    def make_check(
        rid: str = rule_id,
        t: str = title,
        sev: str = severity,
        msg: str = message_template,
        comp: Any = compiled,
    ) -> Any:
        def check(
            self: Rule, tree: ast.AST, source_lines: list[str], path: Path
        ) -> Any:
            for lineno, line in enumerate(source_lines, start=1):
                match = comp.search(line)
                if match:
                    yield Finding(
                        rule_id=rid,
                        title=t,
                        severity=sev,
                        message=msg,
                        file=path,
                        line=lineno,
                        column=match.start(),
                        snippet=line.strip(),
                    )
        return check

    DynamicRule = type(
        "DynamicRule",
        (Rule,),
        {
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "check": make_check(),
        },
    )

    return DynamicRule()
