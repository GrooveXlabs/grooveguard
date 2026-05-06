# GrooveGuard

**GrooveGuard** is a security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server implementations. It uses static analysis to detect secrets, dangerous capabilities, missing input validation, SSRF risks, and overly permissive tools.

## Features

- 🔍 **Secret Detection** — hardcoded API keys, tokens, passwords
- ⚠️ **Dangerous Capabilities** — shell execution, unrestricted file writes
- 🛡️ **Input Validation Gaps** — parameters used in risky calls without checks
- 🌐 **SSRF Detection** — unvalidated URL fetching
- 📊 **Multiple Formats** — JSON, Markdown, SARIF
- 🔧 **Extensible Rules** — YAML-based custom rules
- 🚀 **CI/CD Ready** — configurable exit codes and SARIF output

## Installation

```bash
pip install grooveguard
```

Or from source:

```bash
git clone https://github.com/example/grooveguard.git
cd grooveguard
pip install -e ".[dev]"
```

## Quickstart

```bash
# Scan a directory
grooveguard scan ./my-mcp-server

# Output SARIF for CI/CD
grooveguard scan --format sarif ./my-mcp-server > report.sarif

# Use custom rules
grooveguard scan --rules custom-rules.yaml ./my-mcp-server

# List built-in rules
grooveguard list-rules
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  grooveguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install grooveguard
      - run: grooveguard scan --format sarif --fail-on HIGH . > grooveguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: grooveguard.sarif
```

### Pre-commit Hook

```yaml
repos:
  - repo: local
    hooks:
      - id: grooveguard
        name: GrooveGuard Security Scan
        entry: grooveguard scan --fail-on HIGH
        language: system
        pass_filenames: false
        always_run: true
```

## Rule Suppression

Add a comment to suppress false positives:

```python
api_key = "sk-test"  # grooveguard: ignore=SEC-001
```

Or suppress all rules on a line:

```python
os.system("echo debug")  # grooveguard: ignore
```

## Custom Rules

Create a YAML file:

```yaml
rules:
  - id: "CUST-001"
    title: "Debug mode enabled"
    severity: "MEDIUM"
    pattern: "debug\s*=\s*True"
    message: "Debug mode should not be enabled in production."
```

Then pass it to the CLI:

```bash
grooveguard scan --rules custom-rules.yaml ./my-mcp-server
```

## Architecture

```
grooveguard/
├── scanner.py          # AST-based scanning engine
├── rules/              # Security rule definitions
├── reporters/          # JSON, Markdown, SARIF formatters
├── cli.py              # Click CLI
└── utils.py            # Shared helpers
```

## Security Principles

GrooveGuard is designed with a security-first mindset:

- **Read-only scanning** — never executes code or modifies files
- **Path validation** — resolves and validates all targets before scanning
- **No secrets in code** — the tool itself contains no hardcoded credentials
- **Safe URL handling** — blocks private IP ranges and metadata endpoints

## License

MIT
