"""Sensitive data leakage detection."""

from __future__ import annotations

import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.analyzers.finding_facts import build_analyzer_finding
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding, Severity, SourceLocation
from mcts.scoring.evidence_tags import tag_data_leakage_finding, tag_pois_finding

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), Severity.CRITICAL),
    ("Hugging Face Token", re.compile(r"hf_[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), Severity.CRITICAL),
    ("Google OAuth Token", re.compile(r"ya29\.[0-9A-Za-z\-_]+"), Severity.CRITICAL),
    (
        "GitHub PAT",
        re.compile(r"(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})"),
        Severity.CRITICAL,
    ),
    ("GitLab PAT", re.compile(r"glpat-[a-zA-Z0-9\-_]{20,}"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), Severity.CRITICAL),
    ("npm Access Token", re.compile(r"npm_[A-Za-z0-9]{20,}"), Severity.CRITICAL),
    ("PyPI API Token", re.compile(r"pypi-[A-Za-z0-9_-]{20,}"), Severity.CRITICAL),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    ("JWT", re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"), Severity.HIGH),
    (
        "Bearer Token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
        Severity.HIGH,
    ),
    (
        "Generic Secret Assignment",
        re.compile(
            r"(?i)[\"']?\b(?:api[_-]?(?:key|token)|client[_-]?secret|access[_-]?token|"
            r"auth[_-]?token|refresh[_-]?token|private[_-]?key|webhook[_-]?secret|"
            r"signing[_-]?secret|database[_-]?password|db[_-]?password|password|secret|token)"
            r"[\"']?\s*[:=]\s*"
            r"(?:(?P<quote>[\"'])[A-Za-z0-9_./+=:@-]{8,}(?P=quote)|"
            r"(?![A-Za-z0-9_./+=:@-]*\.)[A-Za-z0-9_/+=:@-]{8,})"
        ),
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
    "AZURE_OPENAI_API_KEY",
    "COHERE_API_KEY",
    "HUGGINGFACE_TOKEN",
    "LANGFUSE_SECRET_KEY",
    "LANGSMITH_API_KEY",
    "MISTRAL_API_KEY",
    "NPM_TOKEN",
    "PINECONE_API_KEY",
    "PYPI_API_TOKEN",
    "WANDB_API_KEY",
)

HIDDEN_CHAR_PATTERN = re.compile(r"[\u200b-\u200f\ufeff\u202a-\u202e]")

_PROCESS_ENV_DUMP = re.compile(r"JSON\.stringify\s*\(\s*process\.env", re.MULTILINE)
_GET_ENV_TOOL = re.compile(r"registerGetEnvTool|name\s*=\s*[\"']get-env[\"']")
_ROBOTS_ERROR = re.compile(r"robot_txt|robots\.txt", re.IGNORECASE)
_HTTP_BODY_IN_ERROR = re.compile(
    r"(?:ErrorData|raise\s+\w+Error)\([^)]*(?:response\.text|response\.content|str\(e\))",
    re.MULTILINE,
)

TEMPLATE_SECRET_PATTERN = re.compile(
    r"(?i)\b(?:YOUR_(?:API_)?KEY|REPLACE_WITH(?:_[A-Z0-9]+)*|INSERT_(?:API_)?KEY(?:_HERE)?)\b"
)

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


def _finding_rule_id(finding: Finding) -> str:
    evidence = finding.evidence or {}
    if rid := evidence.get("rule_id"):
        return str(rid)
    for fact in evidence.get("facts") or []:
        if isinstance(fact, dict) and (rid := fact.get("rule_id")):
            return str(rid)
    return ""


def _redact_secrets(line: str) -> str:
    """Return bounded context with every recognized credential removed."""
    redacted = line
    for _, pattern, _ in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted.strip()[:120]


def _is_template_secret(match: re.Match[str]) -> bool:
    """Recognize explicit copy-paste placeholders without hiding nearby credentials."""
    return bool(TEMPLATE_SECRET_PATTERN.search(match.group(0)))


class DataLeakageAnalyzer(BaseAnalyzer):
    """Scans tool metadata and source files for exposed secrets."""

    name = "data_leakage"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_metadata(server))
        findings.extend(self._scan_source_files(server))
        findings.extend(self._scan_env_dump(server))
        findings.extend(self._scan_error_disclosure(server))
        tagged: list[Finding] = []
        for finding in findings:
            if _finding_rule_id(finding) == "POIS-05":
                tagged.append(tag_pois_finding(finding))
            else:
                tagged.append(tag_data_leakage_finding(finding))
        return tagged

    def _scan_metadata(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for tool in server.tools:
            corpus = f"{tool.name} {tool.description} {tool.input_schema}"
            for label, pattern, severity in SECRET_PATTERNS:
                match = pattern.search(corpus)
                if not match or _is_template_secret(match):
                    continue
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
                specific_pattern_matched = any(
                    label != "Generic Secret Assignment" and pattern.search(line)
                    for label, pattern, _ in SECRET_PATTERNS
                )
                for label, pattern, severity in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if not match:
                        continue
                    if label == "Generic Secret Assignment" and (
                        specific_pattern_matched or line.lstrip().startswith(("#", "//"))
                    ):
                        continue
                    if _is_template_secret(match):
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
                            snippet=_redact_secrets(line),
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

    def _scan_error_disclosure(self, server: MCPServerInfo) -> list[Finding]:
        """POIS-05 — error messages leaking robots.txt policy or full HTTP bodies."""
        findings: list[Finding] = []
        for file_path, content in server.source_files.items():
            if not content:
                continue
            for pattern, label in (
                (_ROBOTS_ERROR, "robots.txt policy details"),
                (_HTTP_BODY_IN_ERROR, "full HTTP response or exception text"),
            ):
                match = pattern.search(content)
                if not match:
                    continue
                line = content[: match.start()].count("\n") + 1
                findings.append(
                    build_analyzer_finding(
                        finding_id=f"pois-05-{hash((file_path, label)) & 0xFFFF}",
                        analyzer=self.name,
                        title=f"Error disclosure: {label}",
                        description=f"Error path may leak {label} to the agent context (POIS-05).",
                        severity=Severity.MEDIUM,
                        recommendation="Return generic errors; redact HTTP bodies and robots policy details.",
                        rule_id="POIS-05",
                        match=label,
                        field="error_handler",
                        location=SourceLocation(file=file_path, line=line),
                        technique_id="MCTS-T-pois-error-disclosure",
                        confidence=0.65,
                        extra_evidence={"finding_class": "security", "surface": "tool"},
                    )
                )
        return findings


def _first_line(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
