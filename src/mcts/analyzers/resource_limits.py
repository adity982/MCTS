"""High-confidence resource limit / DoS patterns (DOS-01–08 narrow L1)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_resource_limits_finding

_RESPONSE_TEXT = re.compile(r"response\.text|\.text\b", re.MULTILINE)
_SIZE_CAP = re.compile(r"max_length|maxLength|max_bytes|len\s*\(|truncate|[:]\s*\d{3,}", re.MULTILINE)
_HTTPX_GET = re.compile(r"(?:httpx|AsyncClient)[\s\S]{0,400}?\.get\s*\(", re.MULTILINE)
_TIMEOUT = re.compile(r"timeout\s*=", re.MULTILINE)
_ROBOTS_FETCH = re.compile(r"robots\.txt|check_may_autonomously", re.IGNORECASE)
_GIT_LOG_CALL = re.compile(r"\.git\.log\s*\(|repo\.git\.log\s*\(", re.MULTILINE)
_GIT_LOG_BOUND = re.compile(
    r"""
    [-]n\b|
    --max-count|
    \bmax_count\b|
    len\s*\([^)]+\)\s*<\s*max_count|
    iter_commits\s*\([^)]*max_count|
    \[:max_count\]
    """,
    re.VERBOSE | re.IGNORECASE,
)
_GZIP_SYNC = re.compile(r"gzipSync\s*\(", re.MULTILINE)
_MAX_OUTPUT = re.compile(r"maxOutput|max_output|MAX_.*OUTPUT", re.IGNORECASE)
_PYDANTIC_LE = re.compile(r"Field\s*\([^)]*le\s*=|conint\s*\([^)]*le\s*=", re.MULTILINE)
_MAX_COUNT_GET = re.compile(r'arguments\.get\s*\(\s*["\']max_count["\']|max_count', re.MULTILINE)


class ResourceLimitsAnalyzer(BaseAnalyzer):
    name = "resource_limits"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content:
                continue
            findings.extend(self._check_file(path, content))
        return [tag_resource_limits_finding(f) for f in findings]

    def _check_file(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _HTTPX_GET.finditer(content):
            block = match.group(0)
            if not _TIMEOUT.search(block):
                findings.append(
                    _dos_finding(
                        "DOS-02",
                        "httpx get without timeout= in handler",
                        Severity.MEDIUM,
                        path,
                        content[: match.start()].count("\n") + 1,
                    )
                )
        if _ROBOTS_FETCH.search(content) and _HTTPX_GET.search(content) and not _TIMEOUT.search(content):
            findings.append(
                _dos_finding(
                    "DOS-02",
                    "robots.txt fetch without timeout guard",
                    Severity.MEDIUM,
                    path,
                    _line_no(content, _ROBOTS_FETCH),
                )
            )
        for match in _RESPONSE_TEXT.finditer(content):
            start = max(0, match.start() - 200)
            end = min(len(content), match.end() + 200)
            window = content[start:end]
            if not _SIZE_CAP.search(window):
                findings.append(
                    _dos_finding(
                        "DOS-01",
                        "response.text used without size cap in same function region",
                        Severity.MEDIUM,
                        path,
                        content[: match.start()].count("\n") + 1,
                    )
                )
                break
        for line in _unbounded_git_log_lines(content):
            findings.append(
                _dos_finding(
                    "DOS-03",
                    "git.log without -n or max_count bound in enclosing function",
                    Severity.MEDIUM,
                    path,
                    line,
                )
            )
        if _GZIP_SYNC.search(content):
            start = _line_no(content, _GZIP_SYNC) or 1
            region = content.splitlines()[max(0, start - 5) : start + 15]
            if not _MAX_OUTPUT.search("\n".join(region)):
                findings.append(
                    _dos_finding(
                        "DOS-08",
                        "gzipSync without max output cap in same function",
                        Severity.MEDIUM,
                        path,
                        start,
                    )
                )
        if _MAX_COUNT_GET.search(content) and not _PYDANTIC_LE.search(content):
            findings.append(
                _dos_finding(
                    "DOS-05",
                    "max_count from arguments without pydantic le= bound",
                    Severity.MEDIUM,
                    path,
                    _line_no(content, _MAX_COUNT_GET),
                )
            )
        return findings


def _unbounded_git_log_lines(content: str) -> list[int]:
    """Return line numbers for git.log calls lacking bounds in the same function."""
    lines: list[int] = []
    for match in _GIT_LOG_CALL.finditer(content):
        func_body = _enclosing_function_body(content, match.start())
        if _GIT_LOG_BOUND.search(func_body):
            continue
        lines.append(content[: match.start()].count("\n") + 1)
    return lines


def _enclosing_function_body(content: str, offset: int) -> str:
    before = content[:offset]
    def_matches = list(re.finditer(r"^def \w+", before, re.MULTILINE))
    if not def_matches:
        return content[max(0, offset - 120) : min(len(content), offset + 600)]
    start = def_matches[-1].start()
    chunk = content[start:]
    body_lines: list[str] = []
    for line in chunk.splitlines():
        if body_lines and line.startswith("def ") and not line[:1].isspace():
            break
        body_lines.append(line)
        if len(body_lines) > 150:
            break
    return "\n".join(body_lines)

def _dos_finding(
    rule_id: str,
    title: str,
    severity: Severity,
    file: str,
    line: int | None,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"dos-{rule_id.lower()}-{hash((file, line)) & 0xFFFF}",
            analyzer="resource_limits",
            title=title,
            description=f"{title} ({rule_id}).",
            severity=severity,
            recommendation="Add timeouts, byte caps, and bounded pagination to resource-heavy operations.",
        ),
        surface="tool",
        rule_id=rule_id,
        finding_class="reliability",
        analysis_depth="L1",
        file=file,
        line=line,
    )
    return (
        builder.location(file, line)
        .confidence(0.65)
        .fact(rule_id=rule_id, match=title, field="handler", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
