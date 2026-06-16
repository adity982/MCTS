"""HTTP/SSE transport exposure analysis (CAP-01/02, TRANS-*)."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.exposed_endpoint import detect_exposed_endpoint
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_transport_exposure_finding

_APP_LISTEN = re.compile(r"\b(?:app|server)\.listen\s*\(\s*([^,)]+)(?:,\s*([^)]+))?", re.MULTILINE)
_BIND_ALL = re.compile(r'["\']0\.0\.0\.0["\']')
_CORS_WILDCARD = re.compile(
    r"origin\s*:\s*[\"']\*[\"']|cors\s*\(\s*\{[^}]*origin\s*:\s*[\"']\*[\"']",
    re.MULTILINE,
)
_NO_AUTH = re.compile(r"/mcp|StreamableHTTPServerTransport|SSEServerTransport")
_AUTH_MIDDLEWARE = re.compile(
    r"\b(?:auth|bearer|apiKey|requireAuth|authenticate|authorization)\b",
    re.IGNORECASE,
)
_SESSION_ID_QUERY = re.compile(r"sessionId|session-id|mcp-session-id", re.IGNORECASE)
_JSON_LIMIT = re.compile(r"express\.json\s*\(\s*\{[^}]*limit\s*:", re.MULTILINE)
_GET_ENV_TOOL = re.compile(r"get-env|process\.env")
_SESSION_PER_POST = re.compile(
    r"else\s+if\s*\(\s*!sessionId\s*\)|if\s*\(\s*!sessionId\s*\).*\{[^}]*createServer|"
    r"if\s*\(\s*!sessionId\s*\).*\{[^}]*new\s+StreamableHTTPServerTransport",
    re.DOTALL | re.IGNORECASE,
)
_CAP_STUB_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("CAP-05", re.compile(r"trigger-url-elicitation|triggerUrlElicitation"), "URL elicitation capability"),
    ("CAP-06", re.compile(r"elicitation/create|sampling/createMessage"), "Client capability invocation"),
)


class TransportExposureAnalyzer(BaseAnalyzer):
    """Detect unauthenticated or overly permissive HTTP MCP transports."""

    name = "transport_exposure"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        has_get_env = any(t.name == "get-env" for t in server.tools) or any(
            _GET_ENV_TOOL.search(c) for c in server.source_files.values()
        )
        http_transport = server.transport in {"http", "sse", "streamable-http"} or any(
            "/transports/" in p.replace("\\", "/") for p in server.source_files
        )

        for path, content in server.source_files.items():
            if not content or path.endswith("#mcp-block"):
                continue
            if (
                "/transports/" not in path.replace("\\", "/")
                and "transports" not in path
                and not _APP_LISTEN.search(content)
            ):
                continue
            findings.extend(self._analyze_transport_file(path, content, has_get_env, http_transport))

        for rule_id, pattern, desc in _CAP_STUB_PATTERNS:
            for path, content in server.source_files.items():
                if pattern.search(content or ""):
                    findings.append(
                        _transport_finding(
                            rule_id=rule_id,
                            title=f"Static stub: {desc}",
                            description=f"{desc} pattern detected (live validation required).",
                            severity=Severity.MEDIUM,
                            file=path,
                            line=_line_no(content, pattern),
                            confidence=0.5,
                            analysis_depth="L0",
                        )
                    )
        return [tag_transport_exposure_finding(f) for f in findings]

    def _analyze_transport_file(
        self,
        path: str,
        content: str,
        has_get_env: bool,
        http_transport: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in _APP_LISTEN.finditer(content):
            line = content[: match.start()].count("\n") + 1
            host_arg = (match.group(2) or "").strip()
            binds_all = _BIND_ALL.search(host_arg) or not host_arg.strip("\"'")
            localhost_only = "127.0.0.1" in content or "localhost" in host_arg

            if binds_all and not localhost_only:
                severity = Severity.CRITICAL
                if has_get_env and http_transport:
                    severity = Severity.CRITICAL
                findings.append(
                    _transport_finding(
                        rule_id="CAP-01",
                        title="HTTP MCP transport binds all interfaces",
                        description="app.listen without 127.0.0.1 exposes MCP to the network.",
                        severity=severity,
                        file=path,
                        line=line,
                        confidence=0.85,
                    )
                )
                if detect_exposed_endpoint(
                    {
                        "log_entry": {
                            "c-uri-path": "/mcp",
                            "cs-host": "0.0.0.0",
                            "c-ip": "203.0.113.1",
                        }
                    }
                ):
                    findings.append(
                        _transport_finding(
                            rule_id="CAP-01",
                            title="Exposed MCP endpoint (NeighborJack static signal)",
                            description=(
                                "Static transport binding matches MCTS-T-1027 exposed endpoint indicators."
                            ),
                            severity=Severity.CRITICAL,
                            file=path,
                            line=line,
                            confidence=0.8,
                            technique_id="MCTS-T-1027",
                        )
                    )

        if _CORS_WILDCARD.search(content):
            findings.append(
                _transport_finding(
                    rule_id="CAP-02",
                    title="CORS wildcard on MCP HTTP transport",
                    description='cors({ origin: "*" }) allows cross-origin MCP access.',
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, _CORS_WILDCARD),
                    confidence=0.8,
                )
            )

        if _NO_AUTH.search(content) and not _AUTH_MIDDLEWARE.search(content):
            findings.append(
                _transport_finding(
                    rule_id="CAP-01",
                    title="MCP HTTP route without authentication middleware",
                    description="HTTP MCP endpoints registered without visible auth middleware.",
                    severity=Severity.CRITICAL if has_get_env else Severity.HIGH,
                    file=path,
                    line=_line_no(content, _NO_AUTH),
                    confidence=0.75,
                )
            )

        if _SESSION_ID_QUERY.search(content) and "app.post" in content.lower():
            findings.append(
                _transport_finding(
                    rule_id="TRANS-03",
                    title="Session identifier in HTTP transport surface",
                    description="Session ID in headers or query enables session fixation/hijack risk.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, _SESSION_ID_QUERY),
                    confidence=0.6,
                )
            )

        if "express" in content and not _JSON_LIMIT.search(content):
            findings.append(
                _transport_finding(
                    rule_id="TRANS-01",
                    title="Missing express.json body size limit",
                    description="HTTP MCP transport without express.json({ limit }) — DoS risk.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, re.compile(r"express\s*\(")),
                    confidence=0.55,
                )
            )

        if _SESSION_PER_POST.search(content):
            findings.append(
                _transport_finding(
                    rule_id="TRANS-06",
                    title="New MCP session created per POST without session reuse guard",
                    description=(
                        "HTTP transport may spawn a new server instance for each unauthenticated POST."
                    ),
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, _SESSION_PER_POST),
                    confidence=0.65,
                )
            )

        if has_get_env and http_transport and _APP_LISTEN.search(content):
            findings.append(
                _transport_finding(
                    rule_id="CAP-03",
                    title="HTTP transport combined with get-env tool",
                    description="Remote MCP access to environment dump tool — automatic Critical chain risk.",
                    severity=Severity.CRITICAL,
                    file=path,
                    line=_line_no(content, _GET_ENV_TOOL),
                    confidence=0.8,
                )
            )
        return findings


def _transport_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str | None = None,
    line: int | None = None,
    confidence: float = 0.75,
    analysis_depth: str = "L1",
    technique_id: str | None = None,
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"trans-{rule_id.lower()}-{hash((file, line, title)) & 0xFFFF}",
            analyzer="transport_exposure",
            title=title,
            description=description,
            severity=severity,
            recommendation=(
                "Bind to 127.0.0.1, require auth middleware, restrict CORS, and gate sensitive tools."
            ),
        ),
        surface="transport",
        rule_id=rule_id,
        finding_class="security",
        analysis_depth=analysis_depth,  # type: ignore[arg-type]
        technique_id=technique_id,
        file=file,
        line=line,
    )
    if file:
        builder = builder.location(file, line)
    return (
        builder.confidence(confidence)
        .fact(rule_id=rule_id, match=title, field="transport", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
