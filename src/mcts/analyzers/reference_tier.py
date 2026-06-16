"""Reference-server tier helpers for demo/downgrade profiles (Phase 2 Step 2.9g)."""

from __future__ import annotations

from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity

_DEMO_MARKERS = (
    "everything",
    "sequential-thinking",
    "sequential_thinking",
    "mcp-server-everything",
)


def is_demo_reference_server(server: MCPServerInfo) -> bool:
    """True for MCP reference demo servers that should not fail CI at full severity."""
    haystack = " ".join(
        [
            server.name.lower(),
            " ".join(server.source_files.keys()).lower(),
            " ".join(server.instruction_sources).lower(),
        ]
    )
    return any(marker in haystack for marker in _DEMO_MARKERS)


def apply_reference_tier(finding: Finding, *, demo: bool) -> Finding:
    """Downgrade demo-server findings one severity level and tag reference_tier."""
    evidence = dict(finding.evidence or {})
    if demo:
        evidence["reference_tier"] = "demo"
        severity = _downgrade_severity(finding.severity)
        return finding.model_copy(update={"severity": severity, "evidence": evidence})
    evidence.setdefault("reference_tier", "production")
    return finding.model_copy(update={"evidence": evidence})


def _downgrade_severity(severity: Severity) -> Severity:
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    try:
        idx = order.index(severity)
    except ValueError:
        return severity
    return order[min(idx + 1, len(order) - 1)]
