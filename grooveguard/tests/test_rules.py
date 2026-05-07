"""Tests for GrooveGuard security rules."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from grooveguard.rules import build_rules
from grooveguard.rules.crypto import InsecureRandomRule, WeakCryptoRule, WeakHashRule
from grooveguard.rules.dangerous import (
    DangerousToolRule,
    FileWriteRule,
    PathTraversalRule,
    ShellExecRule,
)
from grooveguard.rules.injection import (
    CommandInjectionRule,
    EvalExecRule,
    SqlInjectionRule,
    XssRule,
)
from grooveguard.rules.insecure_api import (
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
from grooveguard.rules.secrets import (
    ApiKeyRule,
    BearerTokenRule,
    DatabaseUriRule,
    HardcodedPasswordRule,
    HighEntropyStringRule,
    JwtSecretRule,
    PrivateKeyRule,
    SecretTokenRule,
)
from grooveguard.rules.ssrf import UnvalidatedUrlFetchRule
from grooveguard.rules.validation import MissingValidationRule, UnsafeTypeConversionRule


class TestSecretRules:
    def test_api_key_detection(self, tmp_path: Path) -> None:
        code = 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"'
        tree = ast.parse(code)
        rule = ApiKeyRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-001"
        assert findings[0].severity == "CRITICAL"
        assert findings[0].cwe_id == "CWE-798"

    def test_secret_token_detection(self, tmp_path: Path) -> None:
        code = 'auth_token = "super-secret-token-123"'
        tree = ast.parse(code)
        rule = SecretTokenRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-002"

    def test_hardcoded_password(self, tmp_path: Path) -> None:
        code = 'db_password = "hunter2"'
        tree = ast.parse(code)
        rule = HardcodedPasswordRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-003"

    def test_high_entropy_string(self, tmp_path: Path) -> None:
        code = 'key = "aB3!dEf7Gh9Jk2#m4Np6Qr8St0Uv1Wx3Yz"'
        tree = ast.parse(code)
        rule = HighEntropyStringRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-004"

    def test_jwt_secret(self, tmp_path: Path) -> None:
        code = 'jwt_secret = "my-jwt-signing-key"'
        tree = ast.parse(code)
        rule = JwtSecretRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-005"

    def test_database_uri(self, tmp_path: Path) -> None:
        code = 'DB_URL = "postgresql://admin:secret123@localhost:5432/mydb"'
        tree = ast.parse(code)
        rule = DatabaseUriRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-006"

    def test_private_key(self, tmp_path: Path) -> None:
        code = 'KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA..."'
        tree = ast.parse(code)
        rule = PrivateKeyRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-007"

    def test_bearer_token(self, tmp_path: Path) -> None:
        code = 'header = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"'
        tree = ast.parse(code)
        rule = BearerTokenRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-008"


class TestDangerousRules:
    def test_shell_exec(self, tmp_path: Path) -> None:
        code = "import os\nos.system('ls')"
        tree = ast.parse(code)
        rule = ShellExecRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-001"
        assert findings[0].cwe_id == "CWE-78"

    def test_file_write(self, tmp_path: Path) -> None:
        code = 'open(user_path, "w")'
        tree = ast.parse(code)
        rule = FileWriteRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-002"

    def test_dangerous_tool(self, tmp_path: Path) -> None:
        code = "def run_command(cmd): pass"
        tree = ast.parse(code)
        rule = DangerousToolRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-003"

    def test_path_traversal(self, tmp_path: Path) -> None:
        code = "import os\nos.path.join(base_dir, user_file)"
        tree = ast.parse(code)
        rule = PathTraversalRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-004"


class TestInjectionRules:
    def test_sql_injection(self, tmp_path: Path) -> None:
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        tree = ast.parse(code)
        rule = SqlInjectionRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) >= 1
        assert findings[0].rule_id == "INJ-001"
        assert findings[0].cwe_id == "CWE-89"

    def test_xss(self, tmp_path: Path) -> None:
        code = "from markupsafe import Markup\nresult = mark_safe(user_input)"
        tree = ast.parse(code)
        rule = XssRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) >= 1
        assert findings[0].rule_id == "INJ-002"

    def test_command_injection(self, tmp_path: Path) -> None:
        code = "import subprocess\nsubprocess.run(cmd, shell=True)"
        tree = ast.parse(code)
        rule = CommandInjectionRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "INJ-003"

    def test_eval_exec(self, tmp_path: Path) -> None:
        code = "eval(user_code)"
        tree = ast.parse(code)
        rule = EvalExecRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "INJ-004"


class TestInsecureApiRules:
    def test_pickle(self, tmp_path: Path) -> None:
        code = "import pickle\ndata = pickle.loads(raw)"
        tree = ast.parse(code)
        rule = PickleRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-005"

    def test_yaml_load(self, tmp_path: Path) -> None:
        code = "import yaml\ndata = yaml.load(stream)"
        tree = ast.parse(code)
        rule = YamlLoadRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-006"

    def test_temp_file(self, tmp_path: Path) -> None:
        code = "import tempfile\npath = tempfile.mktemp()"
        tree = ast.parse(code)
        rule = TempFileRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-007"

    def test_marshal(self, tmp_path: Path) -> None:
        code = "import marshal\ndata = marshal.loads(raw)"
        tree = ast.parse(code)
        rule = MarshalRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-008"

    def test_assert_statement(self, tmp_path: Path) -> None:
        code = "assert user.is_authenticated, 'Not authenticated'"
        tree = ast.parse(code)
        rule = AssertStatementRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-009"

    def test_debug_mode(self, tmp_path: Path) -> None:
        code = "DEBUG = True"
        tree = ast.parse(code)
        rule = DebugModeRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-010"

    def test_xml_external_entity(self, tmp_path: Path) -> None:
        code = "import xml.etree.ElementTree\ntree = xml.etree.ElementTree.parse(file)"
        tree = ast.parse(code)
        rule = XmlExternalEntityRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "XML-001"

    def test_ssl_disabled(self, tmp_path: Path) -> None:
        code = "import requests\nr = requests.get(url, verify=False)"
        tree = ast.parse(code)
        rule = SslVerificationDisabledRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "NET-001"

    def test_cors_wildcard(self, tmp_path: Path) -> None:
        code = "CORS_ORIGINS = '*'"
        tree = ast.parse(code)
        rule = CorsWildcardRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "NET-003"

    def test_logging_sensitive(self, tmp_path: Path) -> None:
        code = "import logging\nlogging.info(f'Password: {password}')"
        tree = ast.parse(code)
        rule = LoggingSensitiveDataRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) >= 1
        assert findings[0].rule_id == "LOG-001"


class TestCryptoRules:
    def test_weak_hash(self, tmp_path: Path) -> None:
        code = "import hashlib\nh = hashlib.md5(data)"
        tree = ast.parse(code)
        rule = WeakHashRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "CRY-001"
        assert findings[0].cwe_id == "CWE-328"

    def test_weak_crypto(self, tmp_path: Path) -> None:
        code = "from Crypto.Cipher import DES\ncipher = DES.new(key)"
        tree = ast.parse(code)
        rule = WeakCryptoRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "CRY-002"
        assert findings[0].cwe_id == "CWE-327"

    def test_insecure_random(self, tmp_path: Path) -> None:
        code = "import random\ntoken = random.randint(0, 1000000)"
        tree = ast.parse(code)
        rule = InsecureRandomRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "CRY-003"


class TestValidationRules:
    def test_missing_validation(self, tmp_path: Path) -> None:
        code = """def process(path):
    open(path, 'r')
"""
        tree = ast.parse(code)
        rule = MissingValidationRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "VAL-001"

    def test_unsafe_type_conversion(self, tmp_path: Path) -> None:
        code = "age = int(user_age)"
        tree = ast.parse(code)
        rule = UnsafeTypeConversionRule()
        findings = list(rule.check(tree, code.splitlines(), tmp_path / "test.py"))
        assert len(findings) == 1
        assert findings[0].rule_id == "VAL-002"


class TestBuildRules:
    def test_build_all_rules(self) -> None:
        rules = build_rules()
        assert len(rules) >= 20
        rule_ids = {r.rule_id for r in rules}
        assert "SEC-001" in rule_ids
        assert "DNG-001" in rule_ids
        assert "INJ-001" in rule_ids
        assert "CRY-001" in rule_ids

    def test_config_disable_rule(self) -> None:
        from grooveguard.config import Config, RuleConfig

        config = Config()
        config.rules["SEC-001"] = RuleConfig(enabled=False)
        rules = build_rules(config=config)
        rule_ids = {r.rule_id for r in rules}
        assert "SEC-001" not in rule_ids
