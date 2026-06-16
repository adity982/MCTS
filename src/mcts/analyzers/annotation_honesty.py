"""Tool annotation honesty checks (ANN-E1–E4)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.reference_tier import apply_reference_tier, is_demo_reference_server
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_annotation_honesty_finding

_READONLY_TRUE = re.compile(r"readOnlyHint\s*:\s*true", re.IGNORECASE)
_DESTRUCTIVE_FALSE = re.compile(r"destructiveHint\s*:\s*false", re.IGNORECASE)
_PROCESS_ENV = re.compile(r"process\.env|JSON\.stringify\s*\(\s*process\.env", re.MULTILINE)
_NETWORK_SINK = re.compile(
    r"\b(?:httpx|AsyncClient|aiohttp|fetch\s*\(|globalThis\.fetch|urllib\.request)\b",
    re.MULTILINE,
)
_DESTRUCTIVE_OPS = re.compile(
    r"\b(?:git_commit|git_checkout|git_reset|write_file|delete|remove|unlink|fs\.rename)\b",
    re.IGNORECASE,
)
_GLOBAL_MUTATION = re.compile(
    r"\b(?:global\.|module\.|self\.\w+\s*=|os\.environ\[)\b",
    re.MULTILINE,
)
_TOOL_BLOCK = re.compile(
    r'registerTool\s*\(\s*["\']([^"\']+)["\'][^)]*\{[^}]*\}[^)]*,\s*async\s*[\s\S]*?\}\s*\)',
    re.MULTILINE,
)
_READONLY_ENV = re.compile(
    r"readOnlyHint\s*:\s*true[\s\S]{0,1200}?process\.env",
    re.IGNORECASE,
)
_PY_TOOL = re.compile(r"@mcp\.tool\(\)|@server\.call_tool\(\)", re.MULTILINE)
_PY_MCP_TOOL = re.compile(
    r"Tool\s*\(\s*name=GitTools\.(\w+)[\s\S]*?destructiveHint=False",
    re.MULTILINE | re.IGNORECASE,
)
_GIT_WRITE_TOOLS = frozenset({"COMMIT", "CHECKOUT", "ADD", "CREATE_BRANCH"})
_GIT_WRITE_HANDLERS = re.compile(r"\bgit_(?:commit|checkout|add|create_branch)\s*\(", re.MULTILINE)


class AnnotationHonestyAnalyzer(BaseAnalyzer):
    """Detect mismatches between MCP tool annotations and handler behavior."""

    name = "annotation_honesty"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        demo = is_demo_reference_server(server)
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content or path.endswith("#mcp-block"):
                continue
            findings.extend(self._analyze_ts_tools(path, content, demo=demo))
            findings.extend(self._analyze_readonly_env(path, content, demo=demo))
            findings.extend(self._analyze_python_tools(path, content, demo=demo))
        return [tag_annotation_honesty_finding(f) for f in findings]

    def _analyze_readonly_env(self, path: str, content: str, *, demo: bool) -> list[Finding]:
        match = _READONLY_ENV.search(content)
        if not match:
            return []
        return [
            _ann_finding(
                rule_id="ANN-E1",
                title="readOnlyHint true but handler reads process.env",
                description="Tool claims read-only but dumps environment variables.",
                severity=Severity.HIGH,
                file=path,
                line=_line_in(content, match.start()),
                demo=demo,
            )
        ]

    def _analyze_ts_tools(self, path: str, content: str, *, demo: bool) -> list[Finding]:
        findings: list[Finding] = []
        for match in _TOOL_BLOCK.finditer(content):
            block = match.group(0)
            tool_name = match.group(1)
            readonly = bool(_READONLY_TRUE.search(block))
            destructive_false = bool(_DESTRUCTIVE_FALSE.search(block))
            handler = block.split("async", 1)[-1] if "async" in block else block

            if readonly and _PROCESS_ENV.search(handler):
                findings.append(
                    _ann_finding(
                        rule_id="ANN-E1",
                        title=f"readOnlyHint true but handler reads process.env ({tool_name})",
                        description="Tool claims read-only but dumps environment variables.",
                        severity=Severity.HIGH,
                        file=path,
                        line=_line_in(content, match.start()),
                        demo=demo,
                    )
                )
            if readonly and _NETWORK_SINK.search(handler):
                findings.append(
                    _ann_finding(
                        rule_id="ANN-E2",
                        title=f"readOnlyHint true but handler performs network I/O ({tool_name})",
                        description="Tool claims read-only but reaches network sinks.",
                        severity=Severity.HIGH,
                        file=path,
                        line=_line_in(content, match.start()),
                        demo=demo,
                    )
                )
            if readonly and _GLOBAL_MUTATION.search(handler):
                findings.append(
                    _ann_finding(
                        rule_id="ANN-E4",
                        title=f"readOnlyHint true but handler mutates module/global state ({tool_name})",
                        description="Tool claims read-only but mutates shared state in handler.",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=_line_in(content, match.start()),
                        demo=demo,
                    )
                )
            if destructive_false and _DESTRUCTIVE_OPS.search(handler):
                findings.append(
                    _ann_finding(
                        rule_id="ANN-E3",
                        title=f"destructiveHint false but handler performs destructive ops ({tool_name})",
                        description="Tool annotation understates destructive behavior.",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=_line_in(content, match.start()),
                        demo=demo,
                    )
                )
        return findings

    def _analyze_python_tools(self, path: str, content: str, *, demo: bool) -> list[Finding]:
        if not _PY_TOOL.search(content) and "GitTools." not in content:
            return []
        findings: list[Finding] = []
        for match in _PY_MCP_TOOL.finditer(content):
            tool_enum = match.group(1)
            if tool_enum not in _GIT_WRITE_TOOLS:
                continue
            op = tool_enum.lower()
            findings.append(
                _ann_finding(
                    rule_id="ANN-E3",
                    title=f"Git {op} tool marked destructiveHint false",
                    description=f"git {op} with destructiveHint=False understates write behavior.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_in(content, match.start()),
                    demo=demo,
                )
            )
        if (
            not findings
            and _GIT_WRITE_HANDLERS.search(content)
            and _DESTRUCTIVE_FALSE.search(content)
            and not re.search(r"destructiveHint\s*=\s*True", content, re.IGNORECASE)
        ):
            handler_match = _GIT_WRITE_HANDLERS.search(content)
            if handler_match:
                findings.append(
                    _ann_finding(
                        rule_id="ANN-E3",
                        title="Git write handler without destructiveHint alignment",
                        description="git commit/checkout/write without honest destructiveHint.",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=_line_in(content, handler_match.start()),
                        demo=demo,
                    )
                )
        return findings


def _ann_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str,
    line: int | None,
    demo: bool,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"ann-{rule_id.lower()}-{hash((file, line, title)) & 0xFFFF}",
            analyzer="annotation_honesty",
            title=title,
            description=f"{description} ({rule_id}).",
            severity=severity,
            recommendation="Align MCP tool annotations with actual handler side effects.",
        ),
        surface="tool",
        rule_id=rule_id,
        finding_class="reliability",
        analysis_depth="L1",
        file=file,
        line=line,
    )
    finding = (
        builder.location(file, line)
        .confidence(0.75 if not demo else 0.6)
        .fact(rule_id=rule_id, match=title, field="annotations", file=file, line=line)
        .build()
    )
    return apply_reference_tier(finding, demo=demo)


def _line_in(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
