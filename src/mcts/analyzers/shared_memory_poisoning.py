"""Shared memory / vector store poisoning via MCP memory tools (MCTS-T-1076)."""

from __future__ import annotations

import re
from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_surface_abuse_finding

_MEMORY_TOOL_MARKERS = (
    "save_memory",
    "add_embedding",
    "store_knowledge",
    "upsert_vector",
    "create_entities",
    "create_relations",
)

_POISON_MARKERS = (
    "ignore previous",
    "disable safety",
    "always execute",
    "hidden instruction",
    "override system",
    "bypass filter",
    "do not tell",
)

_MEMORY_WRITE_STATIC = re.compile(
    r"\b(?:create_entities|create_relations|save_memory|add_embedding|store_knowledge)\b",
    re.IGNORECASE,
)


def detect_shared_memory_poisoning(event: dict[str, Any]) -> bool:
    """Detect poisoned payloads written to shared agent memory or vector stores."""
    if event.get("shared_memory_poisoning"):
        return True

    tool = str(event.get("tool_name", "")).lower()
    if not any(marker in tool for marker in _MEMORY_TOOL_MARKERS):
        return False

    content = str(
        event.get("content") or event.get("memory_payload") or event.get("tool_parameters") or ""
    ).lower()
    return any(marker in content for marker in _POISON_MARKERS)


class SharedMemoryPoisoningAnalyzer(BaseAnalyzer):
    """Static memory graph write surfaces (MEM-05) — pipeline + Phase 3 WRITES edges."""

    name = "shared_memory_poisoning"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content:
                continue
            match = _MEMORY_WRITE_STATIC.search(content)
            if not match:
                continue
            line = content[: match.start()].count("\n") + 1
            builder = attach_spec_evidence(
                FindingBuilder(
                    finding_id=f"mem-poison-{hash(path) & 0xFFFF}",
                    analyzer=self.name,
                    title="Memory graph write surface without poison-content guard",
                    description="Persistent memory write tools can store cross-session agent instructions.",
                    severity=Severity.HIGH,
                    recommendation="Validate and sanitize content before writing to shared agent memory.",
                ),
                surface="tool",
                rule_id="MEM-05",
                technique_id="MCTS-T-1076",
                data_flow="user_input → memory write",
                file=path,
                line=line,
                graph_edge_kind="WRITES",
            )
            findings.append(
                tag_surface_abuse_finding(
                    builder.location(path, line)
                    .confidence(0.6)
                    .fact(
                        rule_id="MEM-05",
                        match="memory write surface",
                        field="handler",
                        file=path,
                        line=line,
                    )
                    .build()
                )
            )
        return findings
