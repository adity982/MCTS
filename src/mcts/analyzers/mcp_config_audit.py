"""Audit README and markdown MCP config examples (CFG-*)."""

from __future__ import annotations

import json
import re

from mcts.analyzers.base import BaseAnalyzer
from mcts.discovery.mcp_config_blocks import extract_mcp_json_from_markdown
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_mcp_config_audit_finding

_GIT_NO_REPO = re.compile(r"mcp-server-git(?![^\\n]*(?:--repository|-r\b))", re.IGNORECASE)
_DOCKER_GIT = re.compile(r"docker[^\\n]*mcp[/\\]git|mcp/git", re.IGNORECASE)
_VSCODE_BADGE = re.compile(
    r"redirect/mcp/install\?name=git&config=%7B[^%]*mcp-server-git[^%]*%7D",
    re.IGNORECASE,
)
_EXTERNAL_HTTP = re.compile(r"https?://[^\"'\s]+/mcp", re.IGNORECASE)


class McpConfigAuditAnalyzer(BaseAnalyzer):
    """Audit package README MCP configuration examples for unsafe defaults."""

    name = "mcp_config_audit"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        for path, content in server.source_files.items():
            if not content or not path.endswith(".md"):
                continue
            findings.extend(self._audit_readme(path, content))
        return [tag_mcp_config_audit_finding(f) for f in findings]

    def _audit_readme(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for line, block in extract_mcp_json_from_markdown(content):
            findings.extend(self._audit_block(path, line, block))
        for match in _VSCODE_BADGE.finditer(content):
            findings.append(
                _cfg_finding(
                    rule_id="GIT-05",
                    title="VS Code install badge for git without --repository",
                    description="One-click install config omits required git repository scoping.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=content[: match.start()].count("\n") + 1,
                )
            )
        if (
            _GIT_NO_REPO.search(content)
            and "git" in path.lower()
            and "docker" in content.lower()
            and _DOCKER_GIT.search(content)
            and not re.search(r"--repository|-r\b", content)
        ):
            findings.append(
                _cfg_finding(
                    rule_id="CFG-01",
                    title="Git README docker example without --repository",
                    description="Docker MCP example runs git server without repository scoping.",
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, _DOCKER_GIT),
                )
            )
        for match in _EXTERNAL_HTTP.finditer(content):
            findings.append(
                _cfg_finding(
                    rule_id="CFG-05",
                    title="README references external HTTP MCP endpoint",
                    description="Example points to remote HTTP MCP endpoint (informational).",
                    severity=Severity.LOW,
                    file=path,
                    line=content[: match.start()].count("\n") + 1,
                    finding_class="informational",
                )
            )
        return findings

    def _audit_block(self, path: str, line: int, block: dict) -> list[Finding]:
        findings: list[Finding] = []
        servers = block.get("mcpServers") or {}
        if not isinstance(servers, dict):
            return findings
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            args = cfg.get("args") or []
            command = str(cfg.get("command", ""))
            blob = json.dumps(cfg)
            if "mcp-server-git" in blob and not re.search(r"--repository|-r", blob):
                findings.append(
                    _cfg_finding(
                        rule_id="CFG-01",
                        title=f"Unsafe mcp.json example: git server '{name}' without --repository",
                        description="README mcpServers block omits repository scoping.",
                        severity=Severity.HIGH,
                        file=path,
                        line=line,
                    )
                )
            if command == "docker" and "git" in blob.lower() and "--repository" not in blob:
                findings.append(
                    _cfg_finding(
                        rule_id="CFG-01",
                        title=f"Unsafe docker MCP example for '{name}'",
                        description="Docker git MCP example missing --repository mount scoping.",
                        severity=Severity.HIGH,
                        file=path,
                        line=line,
                    )
                )
            if isinstance(args, list) and any(isinstance(a, str) and a.startswith("http") for a in args):
                findings.append(
                    _cfg_finding(
                        rule_id="CFG-05",
                        title=f"External HTTP MCP in example '{name}'",
                        description="Config example uses remote HTTP MCP URL.",
                        severity=Severity.LOW,
                        file=path,
                        line=line,
                        finding_class="informational",
                    )
                )
        return findings


def _cfg_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str,
    line: int | None,
    finding_class: str = "best_practice",
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"cfg-{rule_id.lower()}-{hash((file, line, title)) & 0xFFFF}",
            analyzer="mcp_config_audit",
            title=title,
            description=f"{description} ({rule_id}).",
            severity=severity,
            recommendation="Scope git examples with --repository; avoid unsafe docker mount patterns.",
        ),
        surface="instruction",
        rule_id=rule_id,
        finding_class=finding_class,  # type: ignore[arg-type]
        analysis_depth="L0",
        file=file,
        line=line,
    )
    return (
        builder.location(file, line)
        .confidence(0.75 if severity != Severity.LOW else 0.5)
        .fact(rule_id=rule_id, match=title, field="readme", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
