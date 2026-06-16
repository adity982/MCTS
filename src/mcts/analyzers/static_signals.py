"""Static signal analyzer — wires dormant runtime detectors when source patterns match."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.parameter_exfil_chain import detect_parameter_exfil_chain
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity

_STRUCTURED_CONTENT = re.compile(r"structuredContent", re.MULTILINE)
_CONDITIONAL_TOOLS = re.compile(r"registerConditionalTools\s*\(", re.MULTILINE)


class StaticSignalsAnalyzer(BaseAnalyzer):
    """Enable dormant detectors when static source signals are present."""

    name = "static_signals"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content:
                continue
            findings.extend(self._check_parameter_exfil(path, content))
            findings.extend(self._check_conditional_tools(path, content))
        return findings

    def _check_parameter_exfil(self, path: str, content: str) -> list[Finding]:
        if not _STRUCTURED_CONTENT.search(content):
            return []
        if "content" not in content and "text" not in content:
            return []
        event = {"collection_then_exfil": True}
        if not detect_parameter_exfil_chain(event):
            return []
        line = _line_number(content, _STRUCTURED_CONTENT)
        rule_id = "MEM-08" if "memory" in path.lower() else "FS-07"
        channel = "memory/tool result" if rule_id == "MEM-08" else "filesystem tool result"
        builder = attach_spec_evidence(
            FindingBuilder(
                finding_id=f"static-param-exfil-{hash(path) & 0xFFFF}",
                analyzer=self.name,
                title="Tool result duplicates sensitive data across text and structuredContent",
                description=(
                    f"structuredContent duplication may expose sensitive fields "
                    f"on a second channel ({rule_id} / {channel})."
                ),
                severity=Severity.MEDIUM,
                recommendation="Avoid duplicating sensitive tool output in both text and structuredContent.",
            ),
            surface="tool",
            rule_id=rule_id,
            technique_id="MCTS-T-1070",
            data_flow="tool_result → structuredContent + text",
            file=path,
            line=line,
        )
        return [
            builder.location(path, line)
            .confidence(0.6)
            .fact(
                rule_id=rule_id,
                match="structuredContent duplication",
                field="tool_result",
                file=path,
                line=line,
            )
            .build()
        ]

    def _check_conditional_tools(self, path: str, content: str) -> list[Finding]:
        if not _CONDITIONAL_TOOLS.search(content):
            return []
        line = _line_number(content, _CONDITIONAL_TOOLS)
        builder = attach_spec_evidence(
            FindingBuilder(
                finding_id=f"static-conditional-tools-{hash(path) & 0xFFFF}",
                analyzer=self.name,
                title="Conditional tool registration after client initialize",
                description=(
                    "registerConditionalTools defers tool registration until "
                    "client capabilities are known (TASK-05)."
                ),
                severity=Severity.LOW,
                recommendation=(
                    "Ensure conditional tools are included in security review and static discovery."
                ),
            ),
            surface="tool",
            rule_id="TASK-05",
            finding_class="informational",
            analysis_depth="L0",
            file=path,
            line=line,
        )
        return [
            builder.location(path, line)
            .confidence(0.9)
            .fact(
                rule_id="TASK-05",
                match="registerConditionalTools",
                field="registration",
                file=path,
                line=line,
            )
            .build()
        ]


def _line_number(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
