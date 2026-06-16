"""Network egress and SSRF static analysis (NET-01–06)."""

from __future__ import annotations

import re
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.sast.python.taint import analyze_handler_taint
from mcts.scoring.evidence_tags import tag_network_egress_finding

_FOLLOW_REDIRECTS_TRUE = re.compile(r"follow_redirects\s*=\s*True")
_POST_REDIRECT_REVALIDATION = re.compile(
    r"(?:re-?validat|check).{0,40}redirect|redirect.{0,40}(?:url|host|valid)|response\.url|history\.url",
    re.IGNORECASE,
)
_HTTP_CLIENT_USAGE = re.compile(
    r"\b(?:httpx|AsyncClient|aiohttp|urllib\.request|fetch\s*\(|globalThis\.fetch)",
    re.MULTILINE,
)
_URL_VALIDATION_HINTS = re.compile(
    r"\b(?:RFC1918|private[_\s-]?ip|link[_\s-]?local|169\.254|metadata\.google|"
    r"is_private|block.*host|allowlist|denylist|urlparse|validate.*url|check.*url)\b",
    re.IGNORECASE,
)
_GZIP_ALLOWLIST_DEFAULT_EMPTY = re.compile(
    r"GZIP_ALLOWED_DOMAINS\s*=\s*\(\s*process\.env\.GZIP_ALLOWED_DOMAINS\s*\?\?\s*[\"']{2}\s*\)",
)
_FETCH_NO_REDIRECT_MANUAL = re.compile(r"fetch\s*\([^)]*\{[^}]*redirect\s*:\s*[\"']manual[\"']", re.DOTALL)
_DATA_URI_DECODE = re.compile(r"protocol\s*===\s*[\"']data:[\"']|validateDataURI|data:\s*URI", re.IGNORECASE)
_METADATA_URL = re.compile(r"169\.254\.169\.254|metadata\.google|/latest/meta-data/", re.IGNORECASE)
_PROXY_URL_CLI = re.compile(r"--proxy-url")
_ANYURL_PATTERN = re.compile(r"\bAnyUrl\b")
_HTTPURL_PATTERN = re.compile(r"\bHttpUrl\b")
_NETWORK_TOOL_NAMES = frozenset({"fetch", "gzip-file-as-resource", "http_request", "web_fetch"})


class NetworkEgressAnalyzer(BaseAnalyzer):
    """Detect unguarded outbound HTTP from MCP tool handlers."""

    name = "network_egress"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        module_bodies = list(server.source_files.values())
        has_url_validation = any(_URL_VALIDATION_HINTS.search(body) for body in module_bodies)

        for tool in server.tools:
            module_body = ""
            if tool.source_file and tool.source_file in server.source_files:
                module_body = server.source_files[tool.source_file]
            findings.extend(
                self._analyze_tool(
                    tool,
                    module_body=module_body,
                    has_url_validation=has_url_validation,
                )
            )

        for path, content in server.source_files.items():
            if not content or path.endswith("#mcp-block"):
                continue
            findings.extend(self._analyze_source_file(path, content, has_url_validation))
        return _dedupe_by_rule([tag_network_egress_finding(f) for f in findings])

    def _analyze_tool(
        self,
        tool: MCPTool,
        *,
        module_body: str,
        has_url_validation: bool,
    ) -> list[Finding]:
        snippet = tool.handler_snippet or module_body
        body = snippet
        module_has_http = bool(_HTTP_CLIENT_USAGE.search(module_body))
        is_network_tool = (
            tool.name in _NETWORK_TOOL_NAMES
            or "url" in tool.name.lower()
            or "fetch" in (tool.description or "").lower()
        )

        if not body and not module_has_http:
            return []

        findings: list[Finding] = []
        taint_hit = False
        if body and _looks_like_python(tool.source_file, body):
            taint = analyze_handler_taint(body)
            taint_hit = "http_client" in taint.sinks or any(
                "httpx" in s or "urllib" in s for s in taint.sinks
            )
        elif body and _HTTP_CLIENT_USAGE.search(body):
            taint_hit = True

        if taint_hit or (is_network_tool and module_has_http):
            severity = Severity.CRITICAL if not has_url_validation else Severity.HIGH
            findings.append(
                _net_finding(
                    rule_id="NET-01",
                    title=f"Handler egress to HTTP client: {tool.name}",
                    description="Tool handler or module reaches an HTTP client sink.",
                    severity=severity,
                    tool=tool.name,
                    file=tool.source_file,
                    line=tool.source_line,
                    data_flow="user_input → http_client",
                    confidence=0.85 if module_has_http else 0.75,
                )
            )
        return findings

    def _analyze_source_file(
        self,
        path: str,
        content: str,
        has_url_validation: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if _FOLLOW_REDIRECTS_TRUE.search(content) and not _POST_REDIRECT_REVALIDATION.search(content):
            line = _line_no(content, _FOLLOW_REDIRECTS_TRUE)
            findings.append(
                _net_finding(
                    rule_id="NET-02",
                    title="httpx follow_redirects enabled without redirect re-validation",
                    description="follow_redirects=True without post-redirect URL policy in the same module.",
                    severity=Severity.HIGH,
                    file=path,
                    line=line,
                    data_flow="redirect → internal URL",
                    confidence=0.8,
                )
            )

        if "gzip-file-as-resource" in path or "gzip" in Path(path).name.lower():
            if _HTTP_CLIENT_USAGE.search(content) and not _FETCH_NO_REDIRECT_MANUAL.search(content):
                findings.append(
                    _net_finding(
                        rule_id="NET-03",
                        title="fetch() without redirect: manual in gzip tool",
                        description="Gzip resource tool fetches URLs without manual redirect handling.",
                        severity=Severity.HIGH,
                        file=path,
                        line=_line_no(content, re.compile(r"\bfetch\s*\(")),
                        data_flow="url → fetch → resource",
                        confidence=0.75,
                    )
                )
            if _GZIP_ALLOWLIST_DEFAULT_EMPTY.search(content) or (
                "GZIP_ALLOWED_DOMAINS" in content and "filter((d) => d.length > 0)" in content
            ):
                findings.append(
                    _net_finding(
                        rule_id="NET-04",
                        title="Empty gzip domain allowlist permits all hosts",
                        description="GZIP_ALLOWED_DOMAINS defaults empty — all domains allowed.",
                        severity=Severity.HIGH,
                        file=path,
                        line=_line_no(content, re.compile(r"GZIP_ALLOWED_DOMAINS")),
                        confidence=0.85,
                    )
                )
            if (
                _DATA_URI_DECODE.search(content)
                and "validateDataURI" in content
                and "data:" in content
                and "maxBytes" not in content[: content.find("validateDataURI")]
            ):
                findings.append(
                    _net_finding(
                        rule_id="NET-06",
                        title="data: URI accepted in gzip tool without size cap at decode",
                        description="data: protocol URLs decoded before byte cap enforcement.",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=_line_no(content, re.compile(r"data:")),
                        confidence=0.55,
                    )
                )

        if _METADATA_URL.search(content):
            findings.append(
                _net_finding(
                    rule_id="NET-05",
                    title="Cloud metadata URL pattern in source",
                    description="Metadata endpoint URL pattern present in network-capable module.",
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, _METADATA_URL),
                    confidence=0.6,
                )
            )

        if _PROXY_URL_CLI.search(content) and _HTTP_CLIENT_USAGE.search(content):
            findings.append(
                _net_finding(
                    rule_id="NET-05",
                    title="Proxy URL CLI combined with network egress",
                    description=(
                        "--proxy-url allows attacker-influenced egress path when combined with HTTP tools."
                    ),
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, _PROXY_URL_CLI),
                    confidence=0.7,
                )
            )

        if (
            _ANYURL_PATTERN.search(content)
            and not _HTTPURL_PATTERN.search(content)
            and ("fetch" in Path(path).name or "server.py" in path)
        ):
            findings.append(
                _net_finding(
                    rule_id="NET-06",
                    title="AnyUrl accepts non-HTTP schemes",
                    description=(
                        "Pydantic AnyUrl used instead of HttpUrl — non-http schemes may be accepted."
                    ),
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, _ANYURL_PATTERN),
                    confidence=0.65,
                )
            )
        return findings


def _net_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str | None = None,
    line: int | None = None,
    tool: str | None = None,
    data_flow: str | None = None,
    confidence: float = 0.75,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"net-{rule_id.lower()}-{hash((file, line, tool, title)) & 0xFFFF}",
            analyzer="network_egress",
            title=title,
            description=description,
            severity=severity,
            recommendation=(
                "Add URL allowlist, block RFC1918/metadata hosts, and disable blind redirect following."
            ),
        ),
        surface="tool",
        rule_id=rule_id,
        finding_class="security",
        analysis_depth="L1",
        technique_id=f"MCTS-T-{rule_id.lower()}",
        data_flow=data_flow,
        file=file,
        line=line,
    )
    if tool:
        builder = builder.tool(tool)
    if file:
        builder = builder.location(file, line)
    return (
        builder.confidence(confidence)
        .fact(rule_id=rule_id, match=title, field="handler", file=file, line=line, tool=tool)
        .build()
    )


def _looks_like_python(path: str | None, body: str) -> bool:
    if path and path.endswith(".py"):
        return True
    return "def " in body or "async def" in body or "httpx" in body


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1


def _dedupe_by_rule(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, str | None]] = set()
    out: list[Finding] = []
    for finding in findings:
        rule_id = str(finding.evidence.get("rule_id", ""))
        key = (rule_id, finding.location.file if finding.location else None, finding.tool)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
