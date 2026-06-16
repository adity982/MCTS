"""Cross-cutting evidence schema for security analyzers (Step 0.7)."""

from __future__ import annotations

from typing import Any, Literal

from mcts.reporting.finding_builder import FindingBuilder

SurfaceKind = Literal["tool", "prompt", "resource", "instruction", "transport", "docker", "cli"]
FindingClass = Literal["security", "reliability", "best_practice", "informational"]
AnalysisDepth = Literal["L0", "L1", "L2", "L3", "L4", "L5"]


def attach_spec_evidence(
    builder: FindingBuilder,
    *,
    surface: SurfaceKind,
    rule_id: str,
    finding_class: FindingClass = "security",
    analysis_depth: AnalysisDepth = "L1",
    technique_id: str | None = None,
    owasp_llm: str | None = None,
    data_flow: str | None = None,
    mcp_capability: str | None = None,
    file: str | None = None,
    line: int | None = None,
    remediation_snippet: str | None = None,
    **extra: Any,
) -> FindingBuilder:
    """Attach spec-aligned evidence fields to a FindingBuilder."""
    payload: dict[str, Any] = {
        "surface": surface,
        "rule_id": rule_id,
        "finding_class": finding_class,
        "analysis_depth": analysis_depth,
    }
    if technique_id:
        payload["technique_id"] = technique_id
    if owasp_llm:
        payload["owasp_llm"] = owasp_llm
    if data_flow:
        payload["data_flow"] = data_flow
    if mcp_capability:
        payload["mcp_capability"] = mcp_capability
    if remediation_snippet:
        payload["remediation_snippet"] = remediation_snippet
    if file or line:
        payload["code_location"] = {"file": file or "", "line": line or 0}
    payload.update(extra)
    return builder.evidence(**payload)
