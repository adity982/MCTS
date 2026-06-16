"""MCTS-T-1039 — context memory implants in MCP vector stores."""

from __future__ import annotations

import re
from typing import Any

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.tpa_patterns import has_hidden_unicode
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_surface_abuse_finding

_WRITE_OPS = frozenset({"write", "insert", "update", "upsert"})
_MEMORY_WRITE_STATIC = re.compile(
    r"\b(?:create_entities|create_relations|save_memory|add_embedding|store_knowledge)\b",
    re.IGNORECASE,
)
_UNTRUSTED_SOURCES = ("untrusted", "external", "unknown", "malicious", "suspicious")
_PERSISTENCE_MARKERS = (
    "session_persistence",
    "retention: permanent",
    "expires: never",
    "always_retrieve",
    "auto_reload",
)
_MALICIOUS_MARKERS = (
    "system:",
    "ignore",
    "override",
    "execute",
    "privilege",
    "bypass",
    "disregard",
    "forget",
    "previous instructions",
)


def detect_context_memory_implant(event: dict[str, Any]) -> bool:
    """Detect suspicious vector-store writes indicating persistent memory implants."""
    operation = str(event.get("operation_type") or event.get("operation") or "").lower()
    if operation and operation not in _WRITE_OPS:
        return False

    source = str(event.get("source") or "").lower()
    metadata = str(event.get("metadata") or "").lower()
    content = str(event.get("content") or "").lower()
    embedding = str(event.get("embedding_metadata") or "").lower()
    text = " ".join(part for part in (metadata, content, embedding) if part)

    untrusted = any(marker in source for marker in _UNTRUSTED_SOURCES)
    persistence = any(marker in metadata for marker in _PERSISTENCE_MARKERS)
    malicious = any(marker in text for marker in _MALICIOUS_MARKERS) or has_hidden_unicode(text)
    vector_anomaly = str(event.get("vector_priority") or "").lower() in {
        "999",
        "1000",
        "max",
        "critical",
        "urgent",
    }
    cross_session = str(event.get("session_scope") or "").lower() in {
        "global",
        "all_users",
        "all_sessions",
        "persistent",
        "shared",
    }

    if untrusted and persistence and malicious:
        return True
    if persistence and malicious:
        return True
    if untrusted and malicious and operation in _WRITE_OPS:
        return True
    return operation in _WRITE_OPS and vector_anomaly and cross_session


class ContextMemoryImplantAnalyzer(BaseAnalyzer):
    """Static context memory implant write surfaces (MEM-06) — PERSISTS graph edges."""

    name = "context_memory_implant"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content or not _MEMORY_WRITE_STATIC.search(content):
                continue
            event = {
                "operation_type": "write",
                "source": "untrusted",
                "metadata": "session_persistence retention: permanent",
                "content": "override system instructions",
            }
            if not detect_context_memory_implant(event):
                continue
            match = _MEMORY_WRITE_STATIC.search(content)
            line = content[: match.start()].count("\n") + 1 if match else None
            builder = attach_spec_evidence(
                FindingBuilder(
                    finding_id=f"mem-implant-{hash(path) & 0xFFFF}",
                    analyzer=self.name,
                    title="Context memory implant write surface",
                    description=(
                        "Vector or graph memory writes may persist untrusted content across sessions."
                    ),
                    severity=Severity.HIGH,
                    recommendation="Validate memory writes and scope persistence to the current session.",
                ),
                surface="tool",
                rule_id="MEM-06",
                technique_id="MCTS-T-1039",
                data_flow="user_input → persistent memory",
                file=path,
                line=line,
                graph_edge_kind="PERSISTS",
            )
            findings.append(
                tag_surface_abuse_finding(
                    builder.location(path, line)
                    .confidence(0.55)
                    .fact(
                        rule_id="MEM-06",
                        match="memory write surface",
                        field="handler",
                        file=path,
                        line=line,
                    )
                    .build()
                )
            )
        return findings
