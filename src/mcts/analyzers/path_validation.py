"""Path validation gaps in file-access tool handlers."""

from __future__ import annotations

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.analyzers.path_guards import CANONICALIZATION_HINTS, PATH_ACCESS_HINTS
from mcts.analyzers.tool_classification import is_file_access_tool
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.scoring.evidence_tags import tag_path_validation_finding


class PathValidationAnalyzer(BaseAnalyzer):
    """Flags file tools that lack path canonicalization or traversal guards."""

    name = "path_validation"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if not is_file_access_tool(tool):
                continue
            snippet = tool.handler_snippet or ""
            if tool.source_file and tool.source_file in server.source_files:
                snippet = server.source_files[tool.source_file]
            if not snippet:
                continue
            if not PATH_ACCESS_HINTS.search(snippet):
                continue
            if CANONICALIZATION_HINTS.search(snippet):
                continue
            snippet_preview = snippet.replace("\n", " ").strip()[:160]
            findings.append(
                build_analyzer_finding(
                    finding_id=f"path-missing-validation-{tool.name}",
                    analyzer=self.name,
                    title=f"Missing path validation: {tool.name}",
                    description="File-access tool does not canonicalize or restrict paths.",
                    severity=Severity.HIGH,
                    recommendation="Resolve paths and restrict access to an allowlisted root directory.",
                    rule_id="RULE_PATH_NO_CANONICALIZATION",
                    match="path_canonicalization",
                    field="handler_snippet",
                    tool=tool.name,
                    location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                    technique_id="MCTS-T-1002",
                    confidence=0.7,
                    snippet=snippet_preview,
                    extra_evidence={"missing": "path_canonicalization"},
                )
            )
        return [tag_path_validation_finding(f) for f in findings]
