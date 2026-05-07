"""CWE (Common Weakness Enumeration) taxonomy for GrooveGuard.

Maps rule findings to standardized weakness classifications for
compliance reporting, SARIF output, and enterprise integration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CWEMapping:
    """Maps a GrooveGuard rule to CWE and OWASP classifications."""

    cwe_id: str
    cwe_name: str
    owasp_top10: str | None = None
    owasp_llm: str | None = None
    nist_csf: str | None = None
    remediation: str = ""


# ---------------------------------------------------------------------------
# CWE taxonomy database
# ---------------------------------------------------------------------------

CWE_DATABASE: dict[str, dict[str, Any]] = {
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": "The software contains hard-coded credentials, such as a password or cryptographic key.",
        "owasp_top10": "A07:2021 – Identification and Authentication Failures",
        "remediation": "Store credentials in environment variables, secret managers, or encrypted configuration files.",
    },
    "CWE-259": {
        "name": "Use of Hard-coded Password",
        "description": "The software contains a hard-coded password.",
        "owasp_top10": "A07:2021",
        "remediation": "Use environment variables or a secrets manager for passwords.",
    },
    "CWE-312": {
        "name": "Cleartext Storage of Sensitive Information",
        "description": "The software stores sensitive information in cleartext.",
        "owasp_top10": "A02:2021 – Cryptographic Failures",
        "remediation": "Encrypt sensitive data at rest using strong, industry-standard algorithms.",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": "The software constructs OS commands using externally-influenced input.",
        "owasp_top10": "A03:2021 – Injection",
        "remediation": "Use parameterized APIs. Avoid shell=True. Validate and sanitize all inputs.",
    },
    "CWE-94": {
        "name": "Improper Control of Generation of Code ('Code Injection')",
        "description": "The software constructs all or part of a code segment using externally-influenced input.",
        "owasp_top10": "A03:2021",
        "remediation": "Avoid eval(), exec(), and compile() with untrusted input. Use AST parsing for safe evaluation.",
    },
    "CWE-22": {
        "name": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "The software uses external input to construct a pathname intended to identify a file or directory.",
        "owasp_top10": "A01:2021 – Broken Access Control",
        "remediation": "Use allowlists for permitted paths. Validate and canonicalize all path inputs.",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "description": "The software does not validate or incorrectly validates input.",
        "owasp_top10": "A03:2021",
        "remediation": "Validate all inputs against strict schemas. Reject unexpected data types and values.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The web server receives a URL or similar request from an upstream component and retrieves the contents.",
        "owasp_top10": "A10:2021 – Server-Side Request Forgery",
        "remediation": "Use allowlists for permitted URLs. Disable unnecessary URL schemes. Validate and sanitize URLs.",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": "The software deserializes untrusted data without sufficiently verifying the resulting data.",
        "owasp_top10": "A08:2021 – Software and Data Integrity Failures",
        "remediation": "Avoid deserializing untrusted data. Use JSON instead of pickle. Sign serialized data.",
    },
    "CWE-89": {
        "name": "SQL Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input.",
        "owasp_top10": "A03:2021",
        "remediation": "Use parameterized queries or ORM. Never concatenate user input into SQL.",
    },
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input.",
        "owasp_top10": "A03:2021",
        "remediation": "Encode all output contextually. Use CSP headers. Validate and sanitize input.",
    },
    "CWE-327": {
        "name": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": "The software uses deprecated or broken cryptographic algorithms.",
        "owasp_top10": "A02:2021",
        "remediation": "Use AES-256-GCM, ChaCha20-Poly1305, or Argon2id. Avoid MD5, SHA1, DES, RSA < 2048.",
    },
    "CWE-328": {
        "name": "Use of Weak Hash",
        "description": "The software uses a hashing algorithm that is prone to collisions or brute-force attacks.",
        "owasp_top10": "A02:2021",
        "remediation": "Use SHA-256 or stronger for integrity. Use bcrypt/Argon2id for passwords.",
    },
    "CWE-377": {
        "name": "Insecure Temporary File",
        "description": "Creating and using insecure temporary files can leave application and system data vulnerable.",
        "owasp_top10": "A01:2021",
        "remediation": "Use tempfile.mkstemp() or NamedTemporaryFile(delete=False) with proper permissions.",
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "description": "The software does not validate, or incorrectly validates, a certificate.",
        "owasp_top10": "A02:2021",
        "remediation": "Always verify SSL certificates. Do not disable certificate validation in production.",
    },
    "CWE-532": {
        "name": "Insertion of Sensitive Information into Log File",
        "description": "The software logs sensitive information.",
        "owasp_top10": "A09:2021 – Security Logging and Monitoring Failures",
        "remediation": "Redact passwords, tokens, and PII from logs. Use structured logging with field filtering.",
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "description": "The product exposes sensitive information to actors not explicitly authorized.",
        "owasp_top10": "A01:2021",
        "remediation": "Implement least privilege. Mask sensitive data in responses and logs.",
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "description": "The software does not properly control the allocation and maintenance of a limited resource.",
        "owasp_top10": "A05:2021 – Security Misconfiguration",
        "remediation": "Implement rate limiting, timeouts, and resource quotas.",
    },
    "CWE-776": {
        "name": "Improper Restriction of Recursive Entity References in DTDs",
        "description": "The software permits XML documents containing DTDs that produce entity expansion.",
        "owasp_top10": "A05:2021",
        "remediation": "Disable DTD processing and external entities in XML parsers.",
    },
    "CWE-611": {
        "name": "Improper Restriction of XML External Entity Reference",
        "description": "The software processes XML documents that can contain XML entities with URIs.",
        "owasp_top10": "A05:2021",
        "remediation": "Disable external entities and DTDs in XML parsers. Use JSON when possible.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "The server receives a URL from an upstream component and retrieves the contents.",
        "owasp_top10": "A10:2021",
        "remediation": "Use allowlists for URLs. Block internal IPs and metadata endpoints.",
    },
    "CWE-319": {
        "name": "Cleartext Transmission of Sensitive Information",
        "description": "The software transmits sensitive or security-critical data in cleartext.",
        "owasp_top10": "A02:2021",
        "remediation": "Use TLS 1.2+ for all network communication. Never transmit secrets over HTTP.",
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "description": "The software does not perform any authentication for functionality that requires it.",
        "owasp_top10": "A07:2021",
        "remediation": "Enforce authentication on all sensitive endpoints and administrative functions.",
    },
    "CWE-601": {
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "description": "A web application accepts a user-controlled input that specifies a link.",
        "owasp_top10": "A01:2021",
        "remediation": "Use allowlists for redirect targets. Validate URLs before redirecting.",
    },
    "CWE-917": {
        "name": "Improper Neutralization of Special Elements used in an Expression Language Statement",
        "description": "The software receives input from an upstream component and uses it in an expression.",
        "owasp_top10": "A03:2021",
        "remediation": "Avoid expression languages with untrusted input. Use parameterized templates.",
    },
}


# ---------------------------------------------------------------------------
# Rule → CWE mappings
# ---------------------------------------------------------------------------

RULE_CWE_MAP: dict[str, CWEMapping] = {
    # Secrets
    "SEC-001": CWEMapping("CWE-798", "Use of Hard-coded Credentials", "A07:2021"),
    "SEC-002": CWEMapping("CWE-798", "Use of Hard-coded Credentials", "A07:2021"),
    "SEC-003": CWEMapping("CWE-259", "Use of Hard-coded Password", "A07:2021"),
    "SEC-004": CWEMapping("CWE-312", "Cleartext Storage of Sensitive Information", "A02:2021"),
    "SEC-005": CWEMapping("CWE-798", "Use of Hard-coded Credentials", "A07:2021"),
    "SEC-006": CWEMapping("CWE-798", "Use of Hard-coded Credentials", "A07:2021"),
    "SEC-007": CWEMapping("CWE-798", "Use of Hard-coded Credentials", "A07:2021"),
    "SEC-008": CWEMapping("CWE-798", "Use of Hard-coded Credentials", "A07:2021"),
    # Dangerous operations
    "DNG-001": CWEMapping("CWE-78", "OS Command Injection", "A03:2021"),
    "DNG-002": CWEMapping("CWE-22", "Path Traversal", "A01:2021"),
    "DNG-003": CWEMapping("CWE-94", "Code Injection", "A03:2021"),
    "DNG-004": CWEMapping("CWE-94", "Code Injection", "A03:2021"),
    "DNG-005": CWEMapping("CWE-502", "Deserialization of Untrusted Data", "A08:2021"),
    "DNG-006": CWEMapping("CWE-502", "Deserialization of Untrusted Data", "A08:2021"),
    "DNG-007": CWEMapping("CWE-377", "Insecure Temporary File", "A01:2021"),
    # Validation
    "VAL-001": CWEMapping("CWE-20", "Improper Input Validation", "A03:2021"),
    "VAL-002": CWEMapping("CWE-20", "Improper Input Validation", "A03:2021"),
    # SSRF / Network
    "SSRF-001": CWEMapping("CWE-918", "Server-Side Request Forgery", "A10:2021"),
    "NET-001": CWEMapping("CWE-295", "Improper Certificate Validation", "A02:2021"),
    "NET-002": CWEMapping("CWE-319", "Cleartext Transmission of Sensitive Information", "A02:2021"),
    # Injection
    "INJ-001": CWEMapping("CWE-89", "SQL Injection", "A03:2021"),
    "INJ-002": CWEMapping("CWE-79", "Cross-site Scripting", "A03:2021"),
    "INJ-003": CWEMapping("CWE-94", "Code Injection", "A03:2021"),
    # Crypto
    "CRY-001": CWEMapping("CWE-327", "Use of Broken Cryptographic Algorithm", "A02:2021"),
    "CRY-002": CWEMapping("CWE-328", "Use of Weak Hash", "A02:2021"),
    "CRY-003": CWEMapping("CWE-327", "Use of Broken Cryptographic Algorithm", "A02:2021"),
    # Logging
    "LOG-001": CWEMapping("CWE-532", "Insertion of Sensitive Information into Log File", "A09:2021"),
    # XML
    "XML-001": CWEMapping("CWE-611", "Improper Restriction of XML External Entity Reference", "A05:2021"),
    # Auth
    "AUTH-001": CWEMapping("CWE-306", "Missing Authentication for Critical Function", "A07:2021"),
    # Manifest
    "MANIFEST-001": CWEMapping("CWE-20", "Improper Input Validation", "A03:2021"),
    "MANIFEST-002": CWEMapping("CWE-20", "Improper Input Validation", "A03:2021"),
    "MANIFEST-003": CWEMapping("CWE-20", "Improper Input Validation", "A03:2021"),
    "MANIFEST-004": CWEMapping("CWE-78", "OS Command Injection", "A03:2021"),
    "MANIFEST-005": CWEMapping("CWE-20", "Improper Input Validation", "A03:2021"),
    "MANIFEST-006": CWEMapping("CWE-22", "Path Traversal", "A01:2021"),
    "MANIFEST-007": CWEMapping("CWE-918", "Server-Side Request Forgery", "A10:2021"),
    "MANIFEST-008": CWEMapping("CWE-20", "Improper Input Validation", "A03:2021"),
    # Dependencies
    "DEP-000": CWEMapping("CWE-1104", "Use of Unmaintained Third-Party Components", "A06:2021"),
}


def get_cwe_mapping(rule_id: str) -> CWEMapping | None:
    """Get the CWE mapping for a rule ID."""
    return RULE_CWE_MAP.get(rule_id)


def get_cwe_info(cwe_id: str) -> dict[str, Any] | None:
    """Get full CWE info from the database."""
    return CWE_DATABASE.get(cwe_id)
