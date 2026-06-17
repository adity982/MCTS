"""Capability-overlap chain findings when no proven v3 template path exists."""

from __future__ import annotations

from typing import Any

from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.models import Finding, Severity
from mcts.scoring.evidence_tags import tag_attack_chain_finding


def emit_capability_overlap_findings(server: MCPServerInfo) -> list[Finding]:
    """Legacy overlap parity — single-tool or unproven multi-capability surface."""
    if not server.tools:
        return []
    read_tools = [t for t in server.tools if _cap(t, "reads_untrusted_input")]
    exfil_tools = [t for t in server.tools if _cap(t, "egresses_network")]
    cred_tools = [t for t in server.tools if _cap(t, "accesses_sensitive_data")]
    exec_tools = [t for t in server.tools if _cap(t, "executes_commands")]

    findings: list[Finding] = []
    if read_tools and exfil_tools:
        findings.append(
            _overlap_finding(
                finding_id="chain-read-exfil",
                title="Read → exfiltration attack chain possible",
                description="Tools exist to read data and send it externally.",
                read_tools=read_tools,
                exfil_tools=exfil_tools,
            )
        )
    if read_tools and cred_tools and exfil_tools:
        findings.append(
            _overlap_finding(
                finding_id="chain-credential-theft",
                title="Credential theft chain possible",
                description="Read + credential + egress tools enable multi-step credential exfiltration.",
                read_tools=read_tools,
                credential_tools=cred_tools,
                exfil_tools=exfil_tools,
            )
        )
    if read_tools and exec_tools:
        findings.append(
            _overlap_finding(
                finding_id="chain-read-exec",
                title="Read → command execution chain possible",
                description="Untrusted input can flow from read tools to command execution.",
                read_tools=read_tools,
                exec_tools=exec_tools,
            )
        )
    return [tag_attack_chain_finding(f) for f in findings]


def _overlap_finding(
    *,
    finding_id: str,
    title: str,
    description: str,
    read_tools: list[MCPTool],
    exfil_tools: list[MCPTool] | None = None,
    credential_tools: list[MCPTool] | None = None,
    exec_tools: list[MCPTool] | None = None,
) -> Finding:
    evidence: dict[str, Any] = {"read_tools": [t.name for t in read_tools]}
    if exfil_tools:
        evidence["exfil_tools"] = [t.name for t in exfil_tools]
    if credential_tools:
        evidence["credential_tools"] = [t.name for t in credential_tools]
    if exec_tools:
        evidence["exec_tools"] = [t.name for t in exec_tools]
    builder = (
        FindingBuilder(
            finding_id=finding_id,
            analyzer="attack_graph",
            title=title,
            description=description,
            severity=Severity.CRITICAL,
            recommendation=_recommendation_for(finding_id),
            rule_stability="heuristic",
        )
        .technique("MCTS-T-1005")
        .fact(
            rule_id=finding_id,
            match=", ".join(_all_tool_names(read_tools, exfil_tools, credential_tools, exec_tools)),
            field="capability_overlap",
        )
    )
    for tool in read_tools[:3]:
        if tool.source_file:
            builder = builder.fact(
                rule_id="CAP_READ_TOOL",
                match=tool.name,
                field="reads_untrusted_input",
                file=tool.source_file,
                tool=tool.name,
            )
    if exfil_tools:
        for tool in exfil_tools[:3]:
            if tool.source_file:
                builder = builder.fact(
                    rule_id="CAP_EGRESS_TOOL",
                    match=tool.name,
                    field="egresses_network",
                    file=tool.source_file,
                    tool=tool.name,
                )
    if credential_tools:
        for tool in credential_tools[:3]:
            if tool.source_file:
                builder = builder.fact(
                    rule_id="CAP_CREDENTIAL_TOOL",
                    match=tool.name,
                    field="accesses_sensitive_data",
                    file=tool.source_file,
                    tool=tool.name,
                )
    if exec_tools:
        for tool in exec_tools[:3]:
            if tool.source_file:
                builder = builder.fact(
                    rule_id="CAP_EXEC_TOOL",
                    match=tool.name,
                    field="executes_commands",
                    file=tool.source_file,
                    tool=tool.name,
                )
    return builder.evidence(**evidence).build()


def _recommendation_for(finding_id: str) -> str:
    if finding_id == "chain-read-exfil":
        return "Isolate read and egress tools; require approval for outbound actions."
    if finding_id == "chain-credential-theft":
        return "Block credential tools from agent access or add step-up auth."
    return "Prevent chaining file reads into shell execution without validation."


def _all_tool_names(
    read_tools: list[MCPTool],
    exfil_tools: list[MCPTool] | None,
    credential_tools: list[MCPTool] | None,
    exec_tools: list[MCPTool] | None,
) -> list[str]:
    names: list[str] = [t.name for t in read_tools]
    if exfil_tools:
        names.extend(t.name for t in exfil_tools)
    if credential_tools:
        names.extend(t.name for t in credential_tools)
    if exec_tools:
        names.extend(t.name for t in exec_tools)
    return names


def _cap(tool: MCPTool, field: str) -> bool:
    if not tool.capability:
        return False
    return bool(getattr(tool.capability, field))


def is_legacy_chain_finding(finding: Finding) -> bool:
    if finding.analyzer not in {"attack_chains", "attack_graph"}:
        return False
    if finding.id.startswith("chain-"):
        return True
    template_id = (finding.evidence or {}).get("template_id")
    return isinstance(template_id, str) and bool(template_id)
