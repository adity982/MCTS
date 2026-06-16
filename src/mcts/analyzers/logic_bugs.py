"""Narrow logic bug patterns (LOG-01–06)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_logic_bugs_finding

_DEAD_AND = re.compile(r"&&\s*false|&&\s*0\b|false\s*&&", re.MULTILINE)
_RAISE_EXCEPTIONS_FALSE = re.compile(r"raise_exceptions\s*=\s*False")
_TIMEZONE_IN_SCHEMA = re.compile(r"timezone.*description|description.*timezone", re.IGNORECASE | re.DOTALL)
_STDERR_TOOL_ARGS = re.compile(
    r"stderr.*(?:args|arguments|thoughts)|console\.error\s*\(\s*args", re.IGNORECASE
)
_UNUSED_LIST_REPOS = re.compile(r"def list_repos|async def list_repos", re.MULTILINE)
_ROOTS_USAGE = re.compile(r"roots/list|updateAllowedDirectories", re.IGNORECASE)


class LogicBugsAnalyzer(BaseAnalyzer):
    name = "logic_bugs"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        corpus = "\n".join(server.source_files.values())
        has_roots = bool(_ROOTS_USAGE.search(corpus))
        for path, content in server.source_files.items():
            if not content:
                continue
            if _DEAD_AND.search(content) and "parseResourceId" in content:
                findings.append(
                    _log_finding(
                        "LOG-01",
                        "Dead && branch in URI validation (parseResourceId)",
                        Severity.MEDIUM,
                        path,
                        _line_no(content, _DEAD_AND),
                    )
                )
            if _RAISE_EXCEPTIONS_FALSE.search(content):
                findings.append(
                    _log_finding(
                        "LOG-03",
                        "MCP server run with raise_exceptions=False",
                        Severity.MEDIUM,
                        path,
                        _line_no(content, _RAISE_EXCEPTIONS_FALSE),
                    )
                )
            if _TIMEZONE_IN_SCHEMA.search(content) and "time" in path.lower():
                findings.append(
                    _log_finding(
                        "LOG-04",
                        "Dynamic timezone embedded in tool JSON Schema description",
                        Severity.LOW,
                        path,
                        _line_no(content, _TIMEZONE_IN_SCHEMA),
                        finding_class="informational",
                    )
                )
            if _STDERR_TOOL_ARGS.search(content):
                findings.append(
                    _log_finding(
                        "LOG-05",
                        "stderr logging of full tool arguments or thoughts",
                        Severity.MEDIUM,
                        path,
                        _line_no(content, _STDERR_TOOL_ARGS),
                    )
                )
            if _UNUSED_LIST_REPOS.search(content) and not has_roots:
                findings.append(
                    _log_finding(
                        "LOG-06",
                        "list_repos defined but roots capability not wired",
                        Severity.LOW,
                        path,
                        _line_no(content, _UNUSED_LIST_REPOS),
                        finding_class="best_practice",
                    )
                )
            if "rename" in content and "overwrite" in content.lower() and path.endswith(".md"):
                findings.append(
                    _log_finding(
                        "LOG-02",
                        "Documentation vs fs.rename overwrite behavior mismatch",
                        Severity.LOW,
                        path,
                        1,
                        finding_class="best_practice",
                    )
                )
        return [tag_logic_bugs_finding(f) for f in findings]


def _log_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    file: str,
    line: int | None,
    finding_class: str = "reliability",
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"log-{rule_id.lower()}-{hash((file, line)) & 0xFFFF}",
            analyzer="logic_bugs",
            title=title,
            description=f"{title} ({rule_id}).",
            severity=severity,
            recommendation="Fix logic branches; fail closed on MCP errors; avoid logging sensitive args.",
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
        .confidence(0.6)
        .fact(rule_id=rule_id, match=title, field="source", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
