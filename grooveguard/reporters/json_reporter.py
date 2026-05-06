"""JSON reporter."""

from __future__ import annotations

import json
from typing import Any

from grooveguard.scanner import ScanResult


class JSONReporter:
    """Generate JSON scan reports."""

    @staticmethod
    def generate(result: ScanResult) -> str:
        """Return a JSON string for the scan result."""
        payload: dict[str, Any] = {
            "summary": {
                "files_scanned": result.files_scanned,
                "total_findings": len(result.findings),
                "has_critical_or_high": result.has_critical_or_high,
                "duration_ms": round(result.duration_ms, 2),
            },
            "findings": [f.to_dict() for f in result.findings],
        }
        return json.dumps(payload, indent=2, default=str)
