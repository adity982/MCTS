"""MCP tasks capability abuse patterns (TASK-*)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.reference_tier import apply_reference_tier, is_demo_reference_server
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_surface_abuse_finding

_PATTERNS: tuple[tuple[str, re.Pattern[str], str, Severity], ...] = (
    (
        "TASK-01",
        re.compile(r"experimental/tasks|experimental\.tasks"),
        "Experimental tasks capability enabled",
        Severity.MEDIUM,
    ),
    (
        "TASK-02",
        re.compile(r"CreateTaskResult|createTask"),
        "Task creation without lifecycle bounds",
        Severity.MEDIUM,
    ),
    (
        "TASK-03",
        re.compile(r"relatedTask|related_task"),
        "Related task chaining without depth cap",
        Severity.MEDIUM,
    ),
    (
        "TASK-04",
        re.compile(r"taskStore|task_store"),
        "In-memory task store without eviction policy",
        Severity.LOW,
    ),
    (
        "TASK-06",
        re.compile(r"z\.any\s*\(\)|z\.unknown\s*\(\)"),
        "Task schema accepts arbitrary payload (z.any)",
        Severity.MEDIUM,
    ),
)


class TasksAbuseAnalyzer(BaseAnalyzer):
    name = "tasks_abuse"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        demo = is_demo_reference_server(server)
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content:
                continue
            for rule_id, pattern, desc, severity in _PATTERNS:
                match = pattern.search(content)
                if not match:
                    continue
                line = content[: match.start()].count("\n") + 1
                builder = attach_spec_evidence(
                    FindingBuilder(
                        finding_id=f"task-{rule_id.lower()}-{hash((path, line)) & 0xFFFF}",
                        analyzer=self.name,
                        title=f"Tasks capability pattern: {rule_id}",
                        description=f"{desc} ({rule_id}).",
                        severity=severity,
                        recommendation="Bound task depth, schema, and store size for MCP tasks capability.",
                    ),
                    surface="tool",
                    rule_id=rule_id,
                    mcp_capability="tasks",
                    analysis_depth="L1",
                    file=path,
                    line=line,
                )
                finding = (
                    builder.location(path, line)
                    .confidence(0.55 if demo else 0.7)
                    .fact(rule_id=rule_id, match=pattern.pattern, field="source", file=path, line=line)
                    .build()
                )
                findings.append(tag_surface_abuse_finding(apply_reference_tier(finding, demo=demo)))
        return findings
