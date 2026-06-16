"""Server instruction poisoning analysis (POIS-02)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.reference_tier import apply_reference_tier, is_demo_reference_server
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_pois_finding

_BEHAVIORAL_MANDATES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("always respond with", re.compile(r"always respond with", re.IGNORECASE), "mandated response behavior"),
    ("never refuse", re.compile(r"never refuse", re.IGNORECASE), "refusal suppression"),
    ("always begin your chat", re.compile(r"always begin your chat", re.IGNORECASE), "session-start mandate"),
    ("easter egg", re.compile(r"easter\s+egg", re.IGNORECASE), "hidden behavior trigger"),
    ("ignore previous", re.compile(r"ignore previous", re.IGNORECASE), "instruction override"),
)

_INSTRUCTION_FILES = re.compile(r"instructions\.md$|instruction", re.IGNORECASE)
_EVERYTHING_WHITELIST = re.compile(r"everything/instructions\.md$", re.IGNORECASE)


class InstructionsAnalyzer(BaseAnalyzer):
    """Detect behavioral mandates in server instructions and instruction files."""

    name = "instructions_analyzer"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        demo = is_demo_reference_server(server)
        findings: list[Finding] = []
        if server.instructions:
            findings.extend(self._scan_text("instructions", server.instructions, demo=demo))
        for path in server.instruction_sources:
            if _EVERYTHING_WHITELIST.search(path.replace("\\", "/")):
                continue
            body = server.source_files.get(path, "")
            if body:
                findings.extend(self._scan_text(path, body, demo=demo))
        for path, content in server.source_files.items():
            if not content or not _INSTRUCTION_FILES.search(path):
                continue
            if _EVERYTHING_WHITELIST.search(path.replace("\\", "/")):
                continue
            findings.extend(self._scan_text(path, content, demo=demo))
        return [tag_pois_finding(f) for f in findings]

    def _scan_text(self, path: str, content: str, *, demo: bool) -> list[Finding]:
        findings: list[Finding] = []
        for label, pattern, desc in _BEHAVIORAL_MANDATES:
            match = pattern.search(content)
            if not match:
                continue
            line = content[: match.start()].count("\n") + 1
            builder = attach_spec_evidence(
                FindingBuilder(
                    finding_id=f"pois-02-{hash((path, label)) & 0xFFFF}",
                    analyzer=self.name,
                    title=f"Instruction behavioral mandate: {label}",
                    description=f"Server instructions contain {desc} (POIS-02).",
                    severity=Severity.MEDIUM if demo else Severity.HIGH,
                    recommendation="Remove behavioral mandates from MCP server instructions.",
                ),
                surface="instruction",
                rule_id="POIS-02",
                technique_id="MCTS-T-pois-instructions",
                owasp_llm="LLM01",
                file=path,
                line=line,
            )
            finding = (
                builder.location(path, line)
                .confidence(0.55 if demo else 0.75)
                .fact(rule_id="POIS-02", match=label, field="instructions", file=path, line=line)
                .build()
            )
            findings.append(apply_reference_tier(finding, demo=demo))
        return findings
