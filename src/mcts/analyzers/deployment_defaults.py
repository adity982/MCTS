"""Docker, deployment defaults, and dangerous mount patterns (DEP-*)."""

from __future__ import annotations

import re
from pathlib import Path

from mcts.analyzers.base import BaseAnalyzer
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.finding_evidence import attach_spec_evidence
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_deployment_defaults_finding

_SHELL_ENTRYPOINT = re.compile(r"^ENTRYPOINT\s+(?!.*\[)", re.MULTILINE | re.IGNORECASE)
_EXEC_VAR_LITERAL = re.compile(r'ENTRYPOINT\s*\[[^\]]*"\$\{[^}]+\}"[^\]]*\]', re.MULTILINE)
_DANGEROUS_MOUNT = re.compile(
    r"(?:\$HOME|/workspace|\bmount\b[^\\n]*(?:src=/|src=\$\{|dst=/))",
    re.IGNORECASE,
)
_FS_NO_DIRS = re.compile(r"allowed_dirs\s*=\s*\[\]|allowed_directories\s*=\s*\[\]", re.MULTILINE)
_EGRESS_LABEL = re.compile(r"org\.opencontainers\.image\.|egress.policy|network.policy", re.IGNORECASE)


class DeploymentDefaultsAnalyzer(BaseAnalyzer):
    """Parse Dockerfiles and README/.mcp.json for unsafe deployment defaults."""

    name = "deployment_defaults"

    def analyze(self, server: MCPServerInfo) -> list[Finding]:
        findings: list[Finding] = []
        has_security_md = False
        for path, content in server.source_files.items():
            if not content:
                continue
            if Path(path).name == "Dockerfile":
                findings.extend(self._check_dockerfile(path, content))
            if Path(path).name.upper() == "SECURITY.MD":
                has_security_md = True
            if path.endswith(".md") or path.endswith(".mcp.json"):
                findings.extend(self._check_mounts(path, content))
            if ("filesystem" in path or "mcp_server_filesystem" in path) and _FS_NO_DIRS.search(content):
                findings.append(
                    _dep_finding(
                        rule_id="DEP-03",
                        title="Filesystem server with zero startup allowed directories",
                        description="Roots-only trust — operator must rely on client roots capability.",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=_line_no(content, _FS_NO_DIRS),
                        finding_class="best_practice",
                    )
                )
        if not has_security_md and any("fetch" in p for p in server.source_files):
            findings.append(
                _dep_finding(
                    rule_id="DEP-05",
                    title="No SECURITY.md vulnerability reporting documented",
                    description="Package lacks SECURITY.md for coordinated disclosure (informational).",
                    severity=Severity.LOW,
                    finding_class="informational",
                )
            )
        return [tag_deployment_defaults_finding(f) for f in findings]

    def _check_dockerfile(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        if _SHELL_ENTRYPOINT.search(content):
            findings.append(
                _dep_finding(
                    rule_id="DEP-01",
                    title="Shell-form Dockerfile ENTRYPOINT",
                    description="Shell ENTRYPOINT prevents signal handling and may expand vars unexpectedly.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, _SHELL_ENTRYPOINT),
                )
            )
        if _EXEC_VAR_LITERAL.search(content):
            findings.append(
                _dep_finding(
                    rule_id="DEP-01",
                    title="Exec ENTRYPOINT contains unexpanded ${VAR} literal",
                    description="JSON-array ENTRYPOINT with ${VAR} will not expand at runtime.",
                    severity=Severity.MEDIUM,
                    file=path,
                    line=_line_no(content, _EXEC_VAR_LITERAL),
                )
            )
        if "mcp-server-git" in content and not re.search(r"(--repository|-r\b)", content):
            findings.append(
                _dep_finding(
                    rule_id="DEP-02",
                    title="Git Docker image without required --repository",
                    description="ENTRYPOINT runs mcp-server-git without repository scoping.",
                    severity=Severity.HIGH,
                    file=path,
                    line=_line_no(content, re.compile(r"mcp-server-git")),
                )
            )
        if ("fetch" in path.lower() or "mcp-server-fetch" in content) and not _EGRESS_LABEL.search(content):
            findings.append(
                _dep_finding(
                    rule_id="DEP-04",
                    title="Fetch image without egress policy OCI label",
                    description="No egress/network policy OCI label on container image.",
                    severity=Severity.LOW,
                    file=path,
                    line=1,
                    finding_class="informational",
                )
            )
        return findings

    def _check_mounts(self, path: str, content: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _DANGEROUS_MOUNT.finditer(content):
            if "dst=/" in match.group(0) or "$HOME" in match.group(0):
                findings.append(
                    _dep_finding(
                        rule_id="DEP-03",
                        title="Dangerous bind mount in config or README example",
                        description="Example mounts $HOME or root filesystem into MCP container context.",
                        severity=Severity.MEDIUM,
                        file=path,
                        line=content[: match.start()].count("\n") + 1,
                        finding_class="best_practice",
                    )
                )
        return findings


def _dep_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    file: str | None = None,
    line: int | None = None,
    finding_class: str = "best_practice",
) -> Finding:
    builder = attach_spec_evidence(
        FindingBuilder(
            finding_id=f"dep-{rule_id.lower()}-{hash((file, line, title)) & 0xFFFF}",
            analyzer="deployment_defaults",
            title=title,
            description=f"{description} ({rule_id}).",
            severity=severity,
            recommendation="Use scoped repository paths, exec ENTRYPOINT, and document security contacts.",
        ),
        surface="docker" if file and "Dockerfile" in (file or "") else "instruction",
        rule_id=rule_id,
        finding_class=finding_class,  # type: ignore[arg-type]
        analysis_depth="L0" if finding_class == "informational" else "L1",
        file=file,
        line=line,
    )
    if file:
        builder = builder.location(file, line)
    return (
        builder.confidence(0.7 if severity != Severity.LOW else 0.5)
        .fact(rule_id=rule_id, match=title, field="dockerfile", file=file, line=line)
        .build()
    )


def _line_no(content: str, pattern: re.Pattern[str]) -> int | None:
    match = pattern.search(content)
    if not match:
        return None
    return content[: match.start()].count("\n") + 1
