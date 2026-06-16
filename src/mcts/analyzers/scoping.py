"""Authorization, scoping, deployment defaults, and CLI launch policy (AUTH-*, DUAL-03)."""

from __future__ import annotations

import re
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_scoping_finding

_GIT_UNSCOPED = re.compile(
    r"if\s+allowed_repository\s+is\s+None\s*:\s*\n\s*return",
    re.MULTILINE,
)
_GIT_OPTIONAL_REPO_CLI = re.compile(
    r"@click\.option\s*\([^)]*--repository|add_argument\s*\([^)]*--repository"
)
_ROOTS_REPLACE = re.compile(r"allowed_dirs\s*=|roots.*replace|=\s*roots\b", re.IGNORECASE)
_ROOTS_INTERSECT = re.compile(r"intersect|merge.*roots|is_relative_to", re.IGNORECASE)
_CLIENT_ROOTS = re.compile(
    r"updateAllowedDirectoriesFromRoots|roots/list|roots/list_changed|clientCapabilities.*roots",
    re.IGNORECASE,
)
_ROOTS_REPLACE_BEHAVIOR = re.compile(r"replace[s]?\s+(?:all\s+)?allowed", re.IGNORECASE)
_ALLOWLIST_IN_ERROR = re.compile(r"raise\s+\w+Error\([^)]*allowed", re.IGNORECASE)
_CLI_FLAGS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("DUAL-03", re.compile(r"--ignore-robots-txt"), "ignore-robots-txt bypasses robots policy"),
    ("NET-05", re.compile(r"--proxy-url"), "proxy-url enables attacker-influenced egress"),
    ("FETCH-04", re.compile(r"--custom-user-agent"), "custom user-agent flag on fetch server"),
    ("DUAL-03", re.compile(r"--allow-all-hosts"), "allow-all-hosts disables egress restrictions"),
    ("DUAL-03", re.compile(r"--no-sandbox"), "no-sandbox weakens execution isolation"),
)
_NETWORK_TOOL_HINT = re.compile(
    r"\b(?:fetch|httpx|gzip-file|proxy|http_client|registerTool\s*\(\s*[\"']fetch)\b",
    re.IGNORECASE,
)


class ScopingAnalyzer(BaseAnalyzer):
    """Detect missing authorization boundaries and unsafe CLI defaults."""

    name = "scoping"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        corpus = "\n".join(server.source_files.values())
        cli_sources = _cli_source_text(server)
        has_network = bool(_NETWORK_TOOL_HINT.search(corpus)) or any(
            t.name in {"fetch", "gzip-file-as-resource"} for t in server.tools
        )

        for path, content in server.source_files.items():
            if not content or path.endswith("#mcp-block"):
                continue
            findings.extend(self._check_git(path, content, cli_sources))
            findings.extend(self._check_git_depth(path, content))
            findings.extend(self._check_docker(path, content))
            findings.extend(self._check_filesystem(path, content))
            findings.extend(self._check_allowlist_leak(path, content))
            findings.extend(self._check_cli(path, content, has_network))

        if server.transport == "stdio":
            findings.append(
                _auth_finding(
                    rule_id="AUTH-05",
                    title="Stdio MCP server trust boundary",
                    description=(
                        "Stdio transport grants full process privilege — document operator trust model."
                    ),
                    severity=Severity.LOW,
                    finding_class="informational",
                    confidence=0.9,
                )
            )
        return [tag_scoping_finding(f) for f in findings]

    def _check_git(self, path: str, content: str, cli_sources: str) -> list[Finding]:
        if "mcp_server_git" not in path and "git" not in Path(path).parts:
            return []
        if not _GIT_UNSCOPED.search(content):
            return []
        if not (_GIT_OPTIONAL_REPO_CLI.search(content) or _GIT_OPTIONAL_REPO_CLI.search(cli_sources)):
            return []
        return [
            _auth_finding(
                rule_id="AUTH-01",
                title="Git server allows unscoped repository access by default",
                description="When --repository is omitted, any repo_path is accepted.",
                severity=Severity.CRITICAL,
                file=path,
                line=_line_no(content, _GIT_UNSCOPED),
                confidence=0.85,
            )
        ]

    def _check_git_depth(self, path: str, content: str) -> list[Finding]:
        """GIT-04 — write/checkout tools without scope emphasis (Phase 2 Step 2.9d)."""
        if "git" not in path and "mcp_server_git" not in path:
            return []
        findings: list[Finding] = []
        if re.search(r"git_checkout|git_create_branch", content) and "allowed_repository" not in content:
            findings.append(
                _auth_finding(
                    rule_id="GIT-04",
                    title="Git checkout/branch without repository scope emphasis",
                    description="Branch/checkout tools should enforce allowed_repository scoping.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, re.compile(r"git_checkout|git_create_branch")),
                    confidence=0.55,
                )
            )
        if re.search(r"git_commit", content) and "commit_message" in content:
            findings.append(
                _auth_finding(
                    rule_id="GIT-03",
                    title="Attacker-controlled git commit messages",
                    description="Commit message content is user-controlled (informational).",
                    severity=Severity.LOW,
                    file=path,
                    line=_line_no(content, re.compile(r"git_commit")),
                    confidence=0.4,
                    finding_class="informational",
                )
            )
        return findings

    def _check_docker(self, path: str, content: str) -> list[Finding]:
        if "Dockerfile" not in Path(path).name:
            return []
        if "mcp-server-git" in content and not re.search(r"(--repository|-r\b)", content):
            return [
                _auth_finding(
                    rule_id="AUTH-02",
                    title="Git Docker image without required --repository",
                    description="ENTRYPOINT runs mcp-server-git without -r / --repository scoping.",
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, re.compile(r"mcp-server-git")),
                    confidence=0.8,
                )
            ]
        return []

    def _check_filesystem(self, path: str, content: str) -> list[Finding]:
        if "filesystem" not in path and "mcp_server_filesystem" not in path:
            return []
        findings: list[Finding] = []
        if _ROOTS_REPLACE.search(content) and not _ROOTS_INTERSECT.search(content):
            findings.append(
                _auth_finding(
                    rule_id="AUTH-03",
                    title="Filesystem roots may replace CLI allowlist",
                    description="Client roots appear to replace rather than intersect operator allowlist.",
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, _ROOTS_REPLACE),
                    confidence=0.55,
                )
            )
        if (
            _CLIENT_ROOTS.search(content) or _ROOTS_REPLACE_BEHAVIOR.search(content)
        ) and not _ROOTS_INTERSECT.search(content):
            pattern = _CLIENT_ROOTS if _CLIENT_ROOTS.search(content) else _ROOTS_REPLACE_BEHAVIOR
            findings.append(
                _auth_finding(
                    rule_id="AUTH-04",
                    title="Client roots capability without intersection enforcement",
                    description=(
                        "MCP roots/list updates allowed directories without intersecting CLI allowlist."
                    ),
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, pattern),
                    confidence=0.65,
                )
            )
        return findings

    def _check_allowlist_leak(self, path: str, content: str) -> list[Finding]:
        if not _ALLOWLIST_IN_ERROR.search(content):
            return []
        return [
            _auth_finding(
                rule_id="AUTH-06",
                title="Error message may disclose full allowlist paths",
                description="Exception text embeds allowed path details (FS-08 overlap).",
                severity=Severity.MEDIUM,
                file=path,
                line=_line_no(content, _ALLOWLIST_IN_ERROR),
                confidence=0.5,
            )
        ]

    def _check_cli(self, path: str, content: str, has_network: bool) -> list[Finding]:
        if not has_network:
            return []
        findings: list[Finding] = []
        for rule_id, pattern, desc in _CLI_FLAGS:
            if not pattern.search(content):
                continue
            findings.append(
                _auth_finding(
                    rule_id=rule_id,
                    title=f"Risky CLI flag: {pattern.pattern}",
                    description=f"{desc} in package with network tools.",
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, pattern),
                    confidence=0.8,
                    surface="cli",
                )
            )
        return findings


def _cli_source_text(server: MCPServerInfo) -> str:
    return "\n".join(
        body for src, body in server.source_files.items() if src.endswith("__init__.py") or "argparse" in body
    )


def _auth_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str | None = None,
    line: int | None = None,
    confidence: float = 0.75,
    finding_class: str = "security",
    surface: str = "tool",
) -> Finding:
    depth = "L1" if finding_class == "security" else "L0"
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"scope-{rule_id.lower()}-{hash((file, line, title)) & 0xFFFF}",
            analyzer="scoping",
            title=title,
            description=description,
            severity=severity,
            recommendation="Require operator-scoped boundaries at startup and in Docker/CLI defaults.",
        ),
        surface=surface,  # type: ignore[arg-type]
        rule_id=rule_id,
        finding_class=finding_class,  # type: ignore[arg-type]
        analysis_depth=depth,  # type: ignore[arg-type]
        file=file,
        line=line,
    )
    if file:
        builder = builder.location(file, line)
    return (
        builder.confidence(confidence)
        .fact(rule_id=rule_id, match=title, field="scoping", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
