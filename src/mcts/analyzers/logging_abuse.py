"""MCP logging capability abuse (LOG_CAP-*)."""

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
        "LOG_CAP-01",
        re.compile(r"sendLoggingMessage|logging/message"),
        "Unbounded logging message emission",
        Severity.MEDIUM,
    ),
    (
        "LOG_CAP-02",
        re.compile(r"capabilities\.logging|logging:\s*\{"),
        "Logging capability enabled without rate limit",
        Severity.LOW,
    ),
    (
        "LOG_CAP-03",
        re.compile(r"setInterval\s*\([^)]*sendLogging|setInterval\s*\([^)]*log"),
        "Interval-based log spam",
        Severity.MEDIUM,
    ),
)


class LoggingAbuseAnalyzer(BaseAnalyzer):
    name = "logging_abuse"

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
                        finding_id=f"logcap-{rule_id.lower()}-{hash((path, line)) & 0xFFFF}",
                        analyzer=self.name,
                        title=f"Logging capability abuse: {rule_id}",
                        description=f"{desc} ({rule_id}).",
                        severity=severity,
                        recommendation="Rate-limit logging messages and disable verbose logging by default.",
                    ),
                    surface="tool",
                    rule_id=rule_id,
                    mcp_capability="logging",
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
