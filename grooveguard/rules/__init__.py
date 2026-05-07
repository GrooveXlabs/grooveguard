"""Security rule definitions for GrooveGuard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from grooveguard.scanner import Rule
from grooveguard.utils import load_yaml_safe

from .crypto import InsecureRandomRule, WeakCryptoRule, WeakHashRule
from .dangerous import DangerousToolRule, FileWriteRule, PathTraversalRule, ShellExecRule
from .injection import CommandInjectionRule, EvalExecRule, SqlInjectionRule, XssRule
from .insecure_api import (
    AssertStatementRule,
    CorsWildcardRule,
    DebugModeRule,
    HardcodedIpRule,
    LoggingSensitiveDataRule,
    MarshalRule,
    PickleRule,
    SslVerificationDisabledRule,
    TempFileRule,
    XmlExternalEntityRule,
    YamlLoadRule,
)
from .secrets import (
    ApiKeyRule,
    BearerTokenRule,
    DatabaseUriRule,
    HardcodedPasswordRule,
    HighEntropyStringRule,
    JwtSecretRule,
    PrivateKeyRule,
    SecretTokenRule,
)
from .ssrf import UnvalidatedUrlFetchRule
from .validation import MissingValidationRule, UnsafeTypeConversionRule

__all__ = [
    "build_rules",
    "load_rules_from_yaml",
    "ALL_RULE_CLASSES",
]

ALL_RULE_CLASSES: list[type[Rule]] = [
    # Secrets (SEC-xxx)
    ApiKeyRule,
    SecretTokenRule,
    HardcodedPasswordRule,
    HighEntropyStringRule,
    JwtSecretRule,
    DatabaseUriRule,
    PrivateKeyRule,
    BearerTokenRule,
    # Dangerous operations (DNG-xxx)
    ShellExecRule,
    FileWriteRule,
    DangerousToolRule,
    PathTraversalRule,
    PickleRule,
    YamlLoadRule,
    MarshalRule,
    TempFileRule,
    AssertStatementRule,
    DebugModeRule,
    # Injection (INJ-xxx)
    SqlInjectionRule,
    XssRule,
    CommandInjectionRule,
    EvalExecRule,
    # SSRF / Network (SSRF-xxx, NET-xxx)
    UnvalidatedUrlFetchRule,
    SslVerificationDisabledRule,
    CorsWildcardRule,
    HardcodedIpRule,
    # Validation (VAL-xxx)
    MissingValidationRule,
    UnsafeTypeConversionRule,
    # Crypto (CRY-xxx)
    WeakHashRule,
    WeakCryptoRule,
    InsecureRandomRule,
    # XML (XML-xxx)
    XmlExternalEntityRule,
    # Logging (LOG-xxx)
    LoggingSensitiveDataRule,
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


def build_rules(
    yaml_path: Path | None = None,
    config: Any | None = None,
) -> list[Rule]:
    """Build the default rule set, optionally extended by YAML.

    Args:
        yaml_path: Optional custom YAML rule file.
        config: Optional Config object for rule enable/disable/severity overrides.

    Returns:
        List of Rule instances.
    """
    from grooveguard.config import Config

    rules: list[Rule] = []
    cfg: Config | None = config if isinstance(config, Config) else None

    for rule_cls in ALL_RULE_CLASSES:
        rule = rule_cls()
        # Apply config overrides
        if cfg:
            if not cfg.is_rule_enabled(rule.rule_id):
                continue
            rule.severity = cfg.get_rule_severity(rule.rule_id, rule.severity)
        rules.append(rule)

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
