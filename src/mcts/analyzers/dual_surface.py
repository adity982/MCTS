"""Dual-surface bypass detection — tool vs prompt path divergence (DUAL-01/02)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_dual_surface_finding

_CALL_TOOL = re.compile(
    r"@server\.call_tool\(\)\s*\n\s*async def call_tool[\s\S]*?(?=\n\s*@server\.|\n\s*async def \w+\(|\Z)",
    re.MULTILINE,
)
_GET_PROMPT = re.compile(
    r"@server\.get_prompt\(\)\s*\n\s*async def get_prompt[\s\S]*?(?=\n\s*@server\.|\n\s*async def \w+\(|\Z)",
    re.MULTILINE,
)
_NETWORK_SINK = re.compile(
    r"\b(?:fetch_url|httpx|AsyncClient|aiohttp|urllib\.request|requests\.)\b",
    re.IGNORECASE,
)
_CHECK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Fetch", re.compile(r"\bFetch\s*\(")),
    ("check_may_autonomously_fetch_url", re.compile(r"check_may_autonomously_fetch_url")),
    ("assert_public_http_url", re.compile(r"assert_public_http_url")),
    ("HttpUrl", re.compile(r"\bHttpUrl\b")),
    ("ignore_robots_txt", re.compile(r"ignore_robots_txt")),
)
_CALLEE = re.compile(r"\bawait\s+(\w+)\(|\b(\w+)\(")


class DualSurfaceAnalyzer(BaseAnalyzer):
    """L2 same-file dual-surface checks — tool vs prompt handler divergence."""

    name = "dual_surface"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content or path.endswith("#mcp-block"):
                continue
            tool_match = _CALL_TOOL.search(content)
            prompt_match = _GET_PROMPT.search(content)
            if not tool_match or not prompt_match:
                continue
            tool_body = tool_match.group(0)
            prompt_body = prompt_match.group(0)
            if not _NETWORK_SINK.search(tool_body) or not _NETWORK_SINK.search(prompt_body):
                continue
            findings.extend(
                self._compare_handlers(
                    path, content, tool_body, prompt_body, tool_match.start(), prompt_match.start()
                )
            )
        return [tag_dual_surface_finding(f) for f in findings]

    def _compare_handlers(
        self,
        path: str,
        content: str,
        tool_body: str,
        prompt_body: str,
        tool_offset: int,
        prompt_offset: int,
    ) -> list[Finding]:
        findings: list[Finding] = []
        tool_checks = _extract_checks(tool_body)
        prompt_checks = _extract_checks(prompt_body)
        tool_callees = _callee_set(tool_body)
        prompt_callees = _callee_set(prompt_body)

        missing_in_prompt = tool_checks - prompt_checks
        if missing_in_prompt:
            rule_id = "DUAL-01"
            if "check_may_autonomously_fetch_url" in missing_in_prompt:
                rule_id = "DUAL-02"
            line = _line_in_content(content, prompt_offset)
            desc = "Prompt handler reaches network sinks without the same validation gateway as call_tool."
            if "check_may_autonomously_fetch_url" in missing_in_prompt:
                desc = (
                    "Prompt path skips robots.txt / autonomous fetch policy enforced on tool path (DUAL-02)."
                )
            findings.append(_dual_finding(rule_id, path, line, desc, missing_in_prompt))

        elif not (tool_callees & prompt_callees) and tool_checks != prompt_checks:
            diff = tool_checks.symmetric_difference(prompt_checks)
            if diff:
                findings.append(
                    _dual_finding(
                        "DUAL-02",
                        path,
                        _line_in_content(content, prompt_offset),
                        f"Tool and prompt paths use different validation checks: {sorted(diff)}",
                        diff,
                        confidence=0.45,
                    )
                )
        return findings


def _extract_checks(body: str) -> set[str]:
    return {name for name, pattern in _CHECK_PATTERNS if pattern.search(body)}


def _callee_set(body: str) -> set[str]:
    names: set[str] = set()
    for match in _CALLEE.finditer(body):
        name = match.group(1) or match.group(2)
        if name and name not in {"if", "for", "while", "return", "raise", "await"}:
            names.add(name)
    return names


def _dual_finding(
    rule_id: str,
    path: str,
    line: int,
    description: str,
    checks: set[str],
    confidence: float = 0.55,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"dual-{rule_id.lower()}-{hash((path, line)) & 0xFFFF}",
            analyzer="dual_surface",
            title=f"Dual-surface bypass: {rule_id}",
            description=description,
            severity=Severity.HIGH,
            recommendation="Route tool and prompt handlers through a shared validated gateway.",
        ),
        surface="prompt",
        rule_id=rule_id,
        finding_class="security",
        analysis_depth="L2",
        technique_id="MCTS-T-dual-surface",
        owasp_llm="LLM01",
        data_flow="prompt_input → network_sink (unvalidated)",
        file=path,
        line=line,
    )
    return (
        builder.location(path, line)
        .confidence(confidence)
        .fact(rule_id=rule_id, match=",".join(sorted(checks)), field="get_prompt", file=path, line=line)
        .build()
    )


def _line_in_content(content: str, offset: int) -> int:
    return content[:offset].count("\n") + 1
