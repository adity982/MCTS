"""MCP resources and session resource abuse (RES-*)."""

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
        "RES-03",
        re.compile(r"registerSessionResource|registerSessionResource"),
        "Session-scoped resource without access control",
        Severity.HIGH,
    ),
    (
        "RES-07",
        re.compile(
            r'outputType\s*:\s*["\']resource["\']|outputType\s*===\s*["\']resource["\']'
            r'|\.enum\(\s*\[[^\]]*["\']resource["\']',
            re.IGNORECASE,
        ),
        "Tool output routed to session resource (gzip SSRF chain)",
        Severity.HIGH,
    ),
    (
        "RES-01",
        re.compile(r"SubscribeRequestSchema|resources/subscribe"),
        "Resource subscription without rate limits",
        Severity.MEDIUM,
    ),
    (
        "RES-02",
        re.compile(r"resources/list_changed|listChanged"),
        "Unbounded resource list change notifications",
        Severity.LOW,
    ),
)


class ResourcesAbuseAnalyzer(BaseAnalyzer):
    name = "resources_abuse"

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
                        finding_id=f"res-{rule_id.lower()}-{hash((path, line)) & 0xFFFF}",
                        analyzer=self.name,
                        title=f"Resource abuse pattern: {rule_id}",
                        description=f"{desc} ({rule_id}).",
                        severity=severity,
                        recommendation="Scope session resources; validate URIs before registering resources.",
                    ),
                    surface="resource",
                    rule_id=rule_id,
                    analysis_depth="L1",
                    file=path,
                    line=line,
                )
                finding = (
                    builder.location(path, line)
                    .confidence(0.6 if demo else 0.75)
                    .fact(rule_id=rule_id, match=pattern.pattern, field="source", file=path, line=line)
                    .build()
                )
                findings.append(tag_surface_abuse_finding(apply_reference_tier(finding, demo=demo)))
        return findings
