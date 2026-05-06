# GrooveGuard 🔒

> **MCP Server Security Scanner** — Audit Model Context Protocol servers for secrets, dangerous tools, SSRF, and input validation gaps.

[![CI](https://img.shields.io/badge/tests-23%2F23%20passing-brightgreen)](https://github.com/GrooveXlabs/grooveguard/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## What is GrooveGuard?

[MCP (Model Context Protocol)](https://modelcontextprotocol.io) is exploding — Anthropic, OpenAI, and Microsoft are all pushing it. But **no one is scanning MCP servers for security vulnerabilities**.

GrooveGuard fills that gap. It's a lightweight CLI tool that audits MCP server implementations in seconds.

## Features

| Capability | Description |
|-----------|-------------|
| 🔑 **Secret Detection** | Finds hardcoded API keys, tokens, passwords |
| ⚠️ **Dangerous Tools** | Flags tools that execute shell commands or write files |
| 🌐 **SSRF Detection** | Identifies unvalidated URL fetching in tool handlers |
| ✅ **Input Validation** | Checks if tool inputs are validated before use |
| 📊 **3 Output Formats** | JSON, Markdown, SARIF (for GitHub Code Scanning) |
| 🔧 **Extensible Rules** | YAML-based rules you can customize |
| 🚀 **CI/CD Ready** | Exit code 1 if CRITICAL/HIGH findings exist |

## Quick Start

```bash
# Install
pip install grooveguard

# Scan an MCP server
grooveguard scan ./my-mcp-server

# SARIF output for GitHub Code Scanning
grooveguard scan --format sarif ./my-mcp-server > report.sarif

# Custom rules
grooveguard scan --rules custom-rules.yaml ./my-mcp-server

# List built-in rules
grooveguard list-rules
```

## Example Output

```bash
$ grooveguard scan ./sample-server

🔒 GrooveGuard Security Report
═══════════════════════════════════════

CRITICAL: Hardcoded API key detected
  File: server.py:15
  Match: api_key = "sk-abc123..."
  Rule: secrets.hardcoded_api_key

HIGH: Unvalidated URL fetch
  File: server.py:42
  Tool: fetch_url
  Rule: ssrf.unvalidated_fetch

HIGH: os.system called in tool handler
  File: server.py:58
  Tool: run_command
  Rule: dangerous.shell_execution

Summary: 3 findings (1 CRITICAL, 2 HIGH)
```

## Rule Categories

### Secrets (`rules/secrets.py`)
- Hardcoded API keys (`sk-...`, `ghp_...`)
- Password assignments
- Secret tokens in strings

### Dangerous Capabilities (`rules/dangerous.py`)
- `os.system`, `subprocess.run` in tool handlers
- File write operations (`open(..., 'w')`)
- `eval()` usage
- Dangerous tool names (`run_command`, `exec_code`)

### Input Validation (`rules/validation.py`)
- Missing type hints on tool parameters
- No input sanitization before operations
- Direct parameter passthrough to dangerous functions

### SSRF (`rules/ssrf.py`)
- `requests.get()` with user-controlled URLs
- `urllib` fetches without allowlists
- Missing URL validation before fetching

## CI/CD Integration

```yaml
# .github/workflows/security.yml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install grooveguard
      - run: grooveguard scan --format sarif . > report.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: report.sarif
```

## Architecture

```
grooveguard/
├── scanner.py          # AST-based Python code scanner
├── rules/              # Security rule definitions
│   ├── secrets.py
│   ├── dangerous.py
│   ├── validation.py
│   └── ssrf.py
├── reporters/          # Output formatters
│   ├── json_reporter.py
│   ├── markdown_reporter.py
│   └── sarif_reporter.py
└── cli.py              # Click CLI
```

## Security-First Design

- **Read-only scanning** — Never modifies your code
- **Safe defaults** — Only reads files, never executes
- **No secrets in code** — GrooveGuard itself is clean
- **False positive suppression** — `# grooveguard: ignore` comments

## Development

```bash
git clone https://github.com/GrooveXlabs/grooveguard.git
cd grooveguard
pip install -e ".[dev]"
pytest
```

## License

MIT — Built with ❤️ by GrooveXlabs
