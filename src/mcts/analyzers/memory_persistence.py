"""Persistent memory README patterns and write surfaces (POIS-03, MEM-01–04)."""

from __future__ import annotations

import re
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.reference_tier import apply_reference_tier, is_demo_reference_server
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_pois_finding

_README_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "MEM-01",
        re.compile(r"Always begin your chat by saying", re.IGNORECASE),
        "README mandates session-start memory load",
    ),
    (
        "MEM-02",
        re.compile(r"retrieve all relevant information from your knowledge graph", re.IGNORECASE),
        "README mandates full graph retrieval each session",
    ),
    (
        "MEM-03",
        re.compile(r"read_graph.*every|always.*read_graph", re.IGNORECASE | re.DOTALL),
        "README encourages read_graph on every session",
    ),
)

_MEMORY_WRITE = re.compile(
    r"\b(?:create_entities|create_relations|save_memory|add_embedding|store_knowledge|read_graph)\b",
    re.IGNORECASE,
)
_MEMORY_MIGRATE = re.compile(r"memory\.json.*memory\.jsonl|migrate.*memory\.jsonl", re.IGNORECASE)
_MEMORY_FILE = re.compile(r"MEMORY_FILE_PATH|memory\.json", re.IGNORECASE)


class MemoryPersistenceAnalyzer(BaseAnalyzer):
    """Informational memory persistence and poisoning write surfaces."""

    name = "memory_persistence"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        demo = is_demo_reference_server(server)
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content:
                continue
            if "README" in Path(path).name.upper() or path.endswith(".md"):
                findings.extend(self._check_readme(path, content, demo=demo))
            findings.extend(self._check_write_surfaces(path, content))
            if _MEMORY_FILE.search(content):
                findings.append(
                    _info_finding(
                        rule_id="MEM-04",
                        title="Persistent memory file path configured",
                        description="Memory persistence path detected — document cross-session trust model.",
                        file=path,
                        line=_line_no(content, _MEMORY_FILE),
                    )
                )
            if _MEMORY_MIGRATE.search(content):
                findings.append(
                    _info_finding(
                        rule_id="MEM-09",
                        title="Memory file migrates JSON to JSONL on startup",
                        description="memory.json → memory.jsonl migration on startup (informational).",
                        file=path,
                        line=_line_no(content, _MEMORY_MIGRATE),
                    )
                )
        return findings

    def _check_readme(self, path: str, content: str, *, demo: bool) -> list[Finding]:
        findings: list[Finding] = []
        for rule_id, pattern, desc in _README_PATTERNS:
            match = pattern.search(content)
            if not match:
                continue
            line = content[: match.start()].count("\n") + 1
            builder = attach_spec_evidence(
                FindingBuilder(
                    finding_id=f"mem-readme-{rule_id.lower()}-{hash(path) & 0xFFFF}",
                    analyzer=self.name,
                    title=f"Memory persistence README pattern ({rule_id})",
                    description=f"{desc} (POIS-03 / {rule_id}).",
                    severity=Severity.LOW,
                    recommendation="Document memory trust boundaries; avoid mandatory cross-session loads.",
                ),
                surface="instruction",
                rule_id=rule_id,
                finding_class="informational",
                analysis_depth="L0",
                technique_id="MCTS-T-mem-readme",
                file=path,
                line=line,
            )
            finding = (
                builder.location(path, line)
                .confidence(0.7)
                .fact(rule_id=rule_id, match=desc, field="readme", file=path, line=line)
                .build()
            )
            findings.append(tag_pois_finding(apply_reference_tier(finding, demo=demo)))
        return findings

    def _check_write_surfaces(self, path: str, content: str) -> list[Finding]:
        if not _MEMORY_WRITE.search(content):
            return []
        findings: list[Finding] = []
        line = _line_no(content, _MEMORY_WRITE)
        if re.search(r"\b(?:open_nodes|search_nodes)\b", content, re.IGNORECASE):
            match = re.search(r"\b(?:open_nodes|search_nodes)\b", content, re.IGNORECASE)
            line_no = content[: match.start()].count("\n") + 1 if match else line
            findings.append(
                _mem_read_finding(
                    rule_id="MEM-07",
                    title="Memory subset read tools may exfil poisoned graph nodes",
                    description="search_nodes/open_nodes may return attacker-controlled subgraph.",
                    file=path,
                    line=line_no,
                )
            )
        if "destructiveHint: false" in content and re.search(
            r"delete_entities|delete_relations|delete_observations", content, re.IGNORECASE
        ):
            findings.append(
                _mem_finding(
                    rule_id="MEM-10",
                    title="Memory delete tools marked non-destructive",
                    description="Delete tools with destructiveHint: false mismatch behavior.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=line,
                    confidence=0.6,
                    finding_class="reliability",
                )
            )
        return findings


def _mem_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str,
    line: int | None,
    confidence: float,
    finding_class: str = "security",
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"mem-{rule_id.lower()}-{hash((file, line)) & 0xFFFF}",
            analyzer="memory_persistence",
            title=title,
            description=description,
            severity=severity,
            recommendation="Validate memory writes; scope persistence and document trust model.",
        ),
        surface="tool",
        rule_id=rule_id,
        finding_class=finding_class,  # type: ignore[arg-type]
        analysis_depth="L1",
        file=file,
        line=line,
    )
    return (
        builder.location(file, line)
        .confidence(confidence)
        .fact(rule_id=rule_id, match=title, field="handler", file=file, line=line)
        .build()
    )


def _info_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    file: str,
    line: int | None,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"mem-info-{rule_id.lower()}-{hash((file, line)) & 0xFFFF}",
            analyzer="memory_persistence",
            title=title,
            description=description,
            severity=Severity.LOW,
            recommendation="Document operator trust assumptions for persistent memory.",
        ),
        surface="instruction",
        rule_id=rule_id,
        finding_class="informational",
        analysis_depth="L0",
        file=file,
        line=line,
    )
    return (
        builder.location(file, line)
        .confidence(0.5)
        .fact(rule_id=rule_id, match=title, field="readme", file=file, line=line)
        .build()
    )


def _mem_read_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    file: str,
    line: int | None,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"mem-read-{rule_id.lower()}-{hash((file, line)) & 0xFFFF}",
            analyzer="memory_persistence",
            title=title,
            description=description,
            severity=Severity.LOW,
            recommendation="Validate memory read scopes; document poisoned-graph trust model.",
        ),
        surface="tool",
        rule_id=rule_id,
        finding_class="informational",
        analysis_depth="L0",
        file=file,
        line=line,
        graph_edge_kind="READS",
    )
    return (
        builder.location(file, line)
        .confidence(0.55)
        .fact(rule_id=rule_id, match=title, field="handler", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
