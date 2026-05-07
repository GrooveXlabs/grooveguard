# 🔒 GrooveGuard Enterprise

> **Enterprise-grade Python SAST with AST analysis, CWE mapping, secret detection, and CI/CD integration.**

[![Tests](https://github.com/GrooveXlabs/grooveguard/actions/workflows/test.yml/badge.svg)](https://github.com/GrooveXlabs/grooveguard/actions)
[![Security Scan](https://github.com/GrooveXlabs/grooveguard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/GrooveXlabs/grooveguard/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What is GrooveGuard?

GrooveGuard is a **production-ready static application security testing (SAST) tool** for Python. It analyzes your code using the Python AST (Abstract Syntax Tree) to detect vulnerabilities without executing code.

### Why GrooveGuard over alternatives?

| Feature | GrooveGuard | Bandit | Semgrep |
|---|---|---|---|
| AST-based analysis | ✅ | ✅ | ✅ |
| **30+ built-in rules** | ✅ 30+ | ~70 | 2,500+ |
| **CWE/OWASP mapping** | ✅ Every rule | Partial | Partial |
| **Entropy-based secrets** | ✅ | ❌ | ✅ |
| **Git blame enrichment** | ✅ | ❌ | ❌ |
| **Multiprocessing** | ✅ | ❌ | ✅ |
| **SARIF 2.1.0 output** | ✅ + fingerprints | Basic | ✅ |
| **HTML dashboard** | ✅ | ❌ | ❌ |
| **Config file support** | ✅ `.grooveguard.yml` | ✅ | ✅ |
| **Pre-commit hook** | ✅ | ✅ | ✅ |
| **Policy engine** | ✅ OWASP/NIST | ❌ | ❌ |
| **Dependency scanning** | ✅ pip-audit | ❌ | ❌ |
| **Manifest scanning** | ✅ MCP/JSON | ❌ | ❌ |

---

## Installation

```bash
pip install grooveguard
```

For development:
```bash
pip install -e ".[dev]"
```

---

## Quick Start

### 1. Scan your project

```bash
grooveguard scan .
```

### 2. Generate an HTML report

```bash
grooveguard scan . --format html --output report.html
```

### 3. Export SARIF for GitHub Security tab

```bash
grooveguard scan . --format sarif --output results.sarif
```

### 4. Run with a security policy

```bash
grooveguard policy-scan . --policy owasp-top10 --fail-on HIGH
```

### 5. Initialize configuration

```bash
grooveguard init
```

This creates `.grooveguard.yml` in your project:

```yaml
target: "."
exclude:
  - "*/.git/*"
  - "*/__pycache__/*"
  - "*/venv/*"
min_severity: "LOW"
fail_on: "HIGH"
format: "markdown"
workers: 0
use_git_blame: true
secret_min_entropy: 4.5

rules:
  SEC-004:
    enabled: true
    severity: "MEDIUM"
```

---

## Rule Categories

| Category | Rule IDs | Coverage |
|---|---|---|
| **Secrets** | SEC-001 → SEC-008 | API keys, tokens, passwords, JWT secrets, DB URIs, private keys, Bearer tokens, entropy detection |
| **Dangerous Operations** | DNG-001 → DNG-010 | Shell exec, file writes, path traversal, pickle, YAML, marshal, temp files, asserts, debug mode |
| **Injection** | INJ-001 → INJ-004 | SQL injection, XSS, command injection, eval/exec |
| **Network** | NET-001, NET-003, NET-004 | SSL verification, CORS wildcards, hardcoded IPs |
| **Cryptography** | CRY-001 → CRY-003 | Weak hashes (MD5/SHA1), weak crypto (DES), insecure random |
| **Validation** | VAL-001, VAL-002 | Missing input validation, unsafe type conversion |
| **XML** | XML-001 | XXE (external entity expansion) |
| **Logging** | LOG-001 | Sensitive data in logs |
| **Manifest** | MANIFEST-001 → MANIFEST-008 | MCP/JSON config security |

Every rule maps to:
- **CWE ID** (Common Weakness Enumeration)
- **OWASP Top 10** (2021)
- **Remediation guidance**

---

## Output Formats

| Format | Command | Use Case |
|---|---|---|
| `markdown` | `--format markdown` | Human-readable CLI output |
| `json` | `--format json` | Machine parsing, CI integration |
| `sarif` | `--format sarif` | GitHub Security tab, VS Code, Azure DevOps |
| `html` | `--format html` | Shareable dashboard report |
| `executive` | `--format executive` | CISO/board summaries |
| `remediation` | `--format remediation` | Prioritized fix list |

---

## CI/CD Integration

### GitHub Actions

```yaml
- uses: actions/checkout@v4
- run: pip install grooveguard
- run: grooveguard scan . --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Our repo includes a ready-to-use workflow: `.github/workflows/security-scan.yml`

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/GrooveXlabs/grooveguard
    rev: v1.0.0
    hooks:
      - id: grooveguard
```

### GitLab CI

```yaml
security_scan:
  image: python:3.12
  script:
    - pip install grooveguard
    - grooveguard scan . --fail-on HIGH
  artifacts:
    reports:
      sast: results.sarif
```

---

## Policies

Built-in compliance policies:

| Policy | Standard | Rules |
|---|---|---|
| `owasp-top10` | OWASP Top 10 2021 | All injection, secrets, crypto, auth |
| `owasp-llm` | OWASP Top 10 for LLM | Prompt injection, excessive agency |
| `nist-ai` | NIST AI RMF | Governance, risk, monitoring |
| `mcp-minimal` | MCP Server Baseline | Secrets + dangerous ops |

```bash
grooveguard policy-scan . --policy owasp-top10
```

---

## Advanced Features

### Baseline & Diff

Track only **new** vulnerabilities introduced since your last scan:

```bash
grooveguard baseline . --output baseline.json
grooveguard diff . --baseline baseline.json
```

### Watch Mode

Continuous monitoring during development:

```bash
grooveguard watch . --interval 30
```

### Git Blame Enrichment

Know **who introduced** each vulnerability and **when**:

```bash
grooveguard scan . --no-git-blame=false
```

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────────┐
│   Python    │────▶│  AST Parser │────▶│  Rule Engine    │
│   Source    │     │  (stdlib)   │     │  (30+ rules)    │
└─────────────┘     └─────────────┘     └─────────────────┘
                                                │
                        ┌───────────────────────┼───────────┐
                        ▼                       ▼           ▼
                 ┌─────────────┐      ┌──────────────┐ ┌──────────┐
                 │  CWE Mapper │      │  Reporters   │ │  Policy  │
                 │  + Remediation     │  (6 formats) │ │  Engine  │
                 └─────────────┘      └──────────────┘ └──────────┘
```

---

## Development

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=grooveguard --cov-report=term-missing

# Lint
ruff check .

# Type check
mypy grooveguard
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT © GrooveXlabs
