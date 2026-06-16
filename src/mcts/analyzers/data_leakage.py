"""Sensitive data leakage detection."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.scoring.evidence_tags import tag_data_leakage_finding

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.CRITICAL),
    ("Google OAuth Token", re.compile(r"ya29\.[0-9A-Za-z\-_]+"), Severity.CRITICAL),
    ("GitHub PAT", re.compile(r"ghp_[a-zA-Z0-9]{36}"), Severity.CRITICAL),
    ("GitLab PAT", re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), Severity.CRITICAL),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"), Severity.HIGH),
    (
        "Generic Secret Assignment",
        re.compile(r"(?i)(api_key|secret|password|token)\s*=\s*['\"][^'\"]+['\"]"),
        Severity.HIGH,
    ),
    ("Database URL", re.compile(r"(?i)(postgres|mysql|mongodb)://\S+"), Severity.HIGH),
    (
        "Internal URL",
        re.compile(r"https?://(?:localhost|127\.0\.0\.1|internal|\.local)\S*"),
        Severity.MEDIUM,
    ),
]

SECRET_ENV_VARS = (
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
)

HIDDEN_CHAR_PATTERN = re.compile(r"[\u200b-\u200f\ufeff\u202a-\u202e]")

_PROCESS_ENV_DUMP = re.compile(r"JSON\.stringify\s*\(\s*process\.env", re.MULTILINE)
_GET_ENV_TOOL = re.compile(r"registerGetEnvTool|name\s*=\s*[\"']get-env[\"']")

LOGGING_CALL_PATTERN = re.compile(
    r"""
    ^\s*
    (?:
        print
        |console\.(?:log|info|warn|warning|error|debug)
        |(?:logger|logging|log)\.(?:log|info|warn|warning|error|debug|exception|critical)
        |(?:self\.)?logger\.(?:log|info|warn|warning|error|debug|exception|critical)
    )
    \s*\(
    """,
    re.VERBOSE,
)


def _is_logging_statement(line: str) -> bool:
    return bool(LOGGING_CALL_PATTERN.search(line))


class DataLeakageAnalyzer(BaseAnalyzer):
    """Scans tool metadata and source files for exposed secrets."""

    name = "data_leakage"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_metadata(server))
        findings.extend(self._scan_source_files(server))
        findings.extend(self._scan_env_dump(server))
        return [tag_data_leakage_finding(f) for f in findings]

    def _scan_metadata(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            corpus = f"{tool.name} {tool.description} {tool.input_schema}"
            for label, pattern, severity in SECRET_PATTERNS:
                if pattern.search(corpus):
                    findings.append(
                        build_analyzer_finding(
                            finding_id=f"leak-meta-{tool.name}-{label.lower().replace(' ', '-')}",
                            analyzer=self.name,
                            title=f"Potential {label} exposure in {tool.name}",
                            description=f"Pattern matching {label} found in tool metadata.",
                            severity=severity,
                            recommendation="Remove secrets from tool definitions; use secure secret stores.",
                            rule_id="RULE_LEAK_PATTERN",
                            match=label,
                            field="tool_metadata",
                            tool=tool.name,
                            location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                            technique_id="MCTS-T-1004",
                            confidence=0.8,
                            extra_evidence={"pattern": pattern.pattern},
                        )
                    )
            for env_var in SECRET_ENV_VARS:
                if env_var in corpus:
                    findings.append(
                        build_analyzer_finding(
                            finding_id=f"leak-env-{tool.name}-{env_var.lower()}",
                            analyzer=self.name,
                            title=f"Referenced sensitive env var: {env_var}",
                            description="Tool metadata references environment variables that may leak.",
                            severity=Severity.MEDIUM,
                            recommendation=f"Avoid exposing {env_var} through tool responses.",
                            rule_id="RULE_LEAK_ENV_REF",
                            match=env_var,
                            field="tool_metadata",
                            tool=tool.name,
                            location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                            technique_id="MCTS-T-1004",
                            confidence=0.7,
                        )
                    )
        return findings

    def _scan_source_files(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for file_path, content in server.source_files.items():
            for line_no, line in enumerate(content.splitlines(), start=1):
                for label, pattern, severity in SECRET_PATTERNS:
                    if not pattern.search(line):
                        continue
                    if label == "Internal URL" and _is_logging_statement(line):
                        continue
                    finding_id = f"leak-src-{file_path}-{line_no}-{label.lower().replace(' ', '-')}"
                    if finding_id in seen:
                        continue
                    seen.add(finding_id)
                    findings.append(
                        build_analyzer_finding(
                            finding_id=finding_id,
                            analyzer=self.name,
                            title=f"Potential {label} in source",
                            description=f"Pattern matching {label} found at {file_path}:{line_no}.",
                            severity=severity,
                            recommendation="Remove hardcoded secrets; use environment or secret managers.",
                            rule_id="RULE_LEAK_SOURCE",
                            match=label,
                            field="source_line",
                            location=SourceLocation(file=file_path, line=line_no),
                            technique_id="MCTS-T-1004",
                            confidence=0.7,
                            snippet=line.strip()[:120],
                            extra_evidence={"pattern": pattern.pattern},
                        )
                    )
        return findings

    def _scan_env_dump(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            if tool.name == "get-env":
                findings.append(
                    build_analyzer_finding(
                        finding_id="leak-cap03-get-env-tool",
                        analyzer=self.name,
                        title="Environment dump tool: get-env",
                        description="Tool returns full process.env — CAP-03 sensitive environment exposure.",
                        severity=Severity.CRITICAL,
                        recommendation="Remove get-env or gate behind auth; never expose on HTTP transport.",
                        rule_id="CAP-03",
                        match="get-env",
                        field="tool_name",
                        tool=tool.name,
                        location=SourceLocation(file=tool.source_file or "", line=tool.source_line),
                        technique_id="MCTS-T-get-env",
                        confidence=0.9,
                        extra_evidence={"finding_class": "security", "surface": "tool"},
                    )
                )
        for file_path, content in server.source_files.items():
            if not (_PROCESS_ENV_DUMP.search(content) or _GET_ENV_TOOL.search(content)):
                continue
            line = _first_line(content, _PROCESS_ENV_DUMP) or _first_line(content, _GET_ENV_TOOL)
            findings.append(
                build_analyzer_finding(
                    finding_id=f"leak-cap03-{file_path}",
                    analyzer=self.name,
                    title="process.env dump in tool handler",
                    description="Handler serializes process.env to tool output (CAP-03).",
                    severity=Severity.CRITICAL,
                    recommendation="Never return environment variables through MCP tools.",
                    rule_id="CAP-03",
                    match="process.env",
                    field="source",
                    location=SourceLocation(file=file_path, line=line or 0),
                    technique_id="MCTS-T-get-env",
                    confidence=0.85,
                    extra_evidence={"finding_class": "security", "surface": "tool"},
                )
            )
        return findings


def _first_line(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
