"""Export graph edges from Phase 1/2 analyzer findings."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcts.mcp.models import MCPServerInfo, MCPTool
from mcts.reporting.models import Finding
from mcts.scoring.attack_graph_models import EdgeEvidence, EdgeKind, GraphEdge, GraphLayer, canonical_node_id

_MEMORY_ANALYZERS = frozenset({"shared_memory_poisoning", "context_memory_implant", "memory_persistence"})


def _finding_rule_id(finding: Finding) -> str:
    evidence = finding.evidence or {}
    if rid := evidence.get("rule_id"):
        return str(rid)
    for fact in evidence.get("facts") or []:
        if isinstance(fact, dict) and (rid := fact.get("rule_id")):
            return str(rid)
    return ""


def _finding_tool(finding: Finding) -> str | None:
    if finding.tool:
        return finding.tool
    evidence = finding.evidence or {}
    if tool := evidence.get("tool"):
        return str(tool)
    for fact in evidence.get("facts") or []:
        if isinstance(fact, dict) and fact.get("tool"):
            return str(fact["tool"])
    return None


def _edge_from_finding(
    *,
    kind: EdgeKind,
    from_node: str,
    to_node: str,
    finding: Finding,
    confidence: float = 0.85,
    reachability: float = 1.0,
    label: str = "",
    layer: GraphLayer = GraphLayer.DATAFLOW,
) -> GraphEdge:
    evidence = EdgeEvidence(
        rule_id=_finding_rule_id(finding) or None,
        analyzer=finding.analyzer,
        finding_id=finding.id,
        file=(finding.evidence or {}).get("file"),
        line=(finding.evidence or {}).get("line"),
    )
    from mcts.scoring.attack_graph_models import _edge_id

    return GraphEdge(
        id=_edge_id(kind, from_node, to_node),
        kind=kind,
        from_node=from_node,
        to_node=to_node,
        label=label or _finding_rule_id(finding),
        confidence=confidence,
        reachability=reachability,
        evidence=[evidence],
        layer=layer,
    )


GraphEdgeExporter = Callable[[MCPServerInfo, list[Finding]], list[GraphEdge]]


def export_network_egress_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for finding in findings:
        if finding.analyzer != "network_egress":
            continue
        rule_id = _finding_rule_id(finding)
        if not rule_id.startswith("NET-"):
            continue
        tool = _finding_tool(finding)
        if not tool:
            continue
        edges.append(
            _edge_from_finding(
                kind=EdgeKind.EGRESS,
                from_node=canonical_node_id("tool", tool),
                to_node="sink:external_network",
                finding=finding,
                confidence=finding.confidence or 0.85,
                label=rule_id,
            )
        )
    return edges


def export_transport_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    http_exposed = False
    for finding in findings:
        if finding.analyzer != "transport_exposure":
            continue
        rule_id = _finding_rule_id(finding)
        if rule_id in {"CAP-01", "CAP-02", "TRANS-03"}:
            http_exposed = True
    if not http_exposed:
        return edges
    transport = "transport:http"
    for tool in server.tools:
        edges.append(
            GraphEdge(
                id=f"edge-exposes-{tool.name}",
                kind=EdgeKind.EXPOSES,
                from_node=transport,
                to_node=canonical_node_id("tool", tool.name),
                confidence=0.9,
                reachability=0.9,
                layer=GraphLayer.TRANSPORT,
                label="CAP-01",
            )
        )
    return edges


def export_scoping_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for finding in findings:
        if finding.analyzer != "scoping":
            continue
        tool = _finding_tool(finding)
        if not tool:
            continue
        edges.append(
            _edge_from_finding(
                kind=EdgeKind.READS,
                from_node=canonical_node_id("tool", tool),
                to_node="source:client_roots",
                finding=finding,
                confidence=0.75,
                label=_finding_rule_id(finding),
            )
        )
    return edges


def export_resource_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for finding in findings:
        if finding.analyzer != "resources_abuse":
            continue
        tool = _finding_tool(finding) or "gzip-file-as-resource"
        resource_uri = (finding.evidence or {}).get("resource_uri") or "session/staged"
        edges.append(
            _edge_from_finding(
                kind=EdgeKind.WRITES,
                from_node=canonical_node_id("tool", tool),
                to_node=canonical_node_id("resource", resource_uri),
                finding=finding,
                confidence=0.8,
                label="RES-03",
            )
        )
    return edges


def export_env_read_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for finding in findings:
        if finding.analyzer != "data_leakage":
            continue
        rule_id = _finding_rule_id(finding)
        if rule_id != "CAP-03":
            continue
        tool = _finding_tool(finding) or "get-env"
        edges.append(
            _edge_from_finding(
                kind=EdgeKind.READS,
                from_node=canonical_node_id("tool", tool),
                to_node="sink:env",
                finding=finding,
                confidence=0.9,
                label="CAP-03",
            )
        )
    for tool in server.tools:
        if tool.name in {"get-env", "get_env"} or "process.env" in (tool.description or "").lower():
            edges.append(
                GraphEdge(
                    id=f"edge-reads-env-{tool.name}",
                    kind=EdgeKind.READS,
                    from_node=canonical_node_id("tool", tool.name),
                    to_node="sink:env",
                    confidence=0.85,
                    reachability=1.0,
                    layer=GraphLayer.DATAFLOW,
                    label="CAP-03",
                )
            )
    return edges


def export_dual_surface_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for finding in findings:
        if finding.analyzer != "dual_surface":
            continue
        tool = _finding_tool(finding) or "fetch"
        edges.append(
            _edge_from_finding(
                kind=EdgeKind.EGRESS,
                from_node=canonical_node_id("prompt", tool),
                to_node="sink:external_network",
                finding=finding,
                confidence=0.7,
                label=_finding_rule_id(finding),
            )
        )
    return edges


def _resolve_memory_tool(server: MCPServerInfo, finding: Finding, rule_id: str) -> str | None:
    tool = _finding_tool(finding)
    if tool:
        return tool
    text = f"{finding.title} {finding.description}".lower()
    server_names = {t.name for t in server.tools}
    for candidate in (
        "create_entities",
        "create_relations",
        "add_observations",
        "open_nodes",
        "search_nodes",
        "read_graph",
    ):
        if candidate in text and candidate in server_names:
            return candidate
    if rule_id in {"MEM-05", "MEM-06", "MEM-09"}:
        for name in ("create_entities", "create_relations"):
            if name in server_names:
                return name
    if rule_id == "MEM-07" or "read" in text:
        for name in ("open_nodes", "search_nodes", "read_graph"):
            if name in server_names:
                return name
    return None


def export_memory_poison_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for finding in findings:
        if finding.analyzer not in _MEMORY_ANALYZERS:
            continue
        rule_id = _finding_rule_id(finding)
        tool = _resolve_memory_tool(server, finding, rule_id)
        if not tool:
            continue
        if rule_id in {"MEM-05", "MEM-06"} or "MEM-05" in finding.description:
            edges.append(
                _edge_from_finding(
                    kind=EdgeKind.WRITES,
                    from_node=canonical_node_id("tool", tool),
                    to_node="sink:cross_session",
                    finding=finding,
                    confidence=0.8,
                    label=rule_id or "MEM-05",
                )
            )
        if rule_id == "MEM-09" or "persist" in finding.description.lower():
            edges.append(
                _edge_from_finding(
                    kind=EdgeKind.PERSISTS,
                    from_node=canonical_node_id("tool", tool),
                    to_node="sink:cross_session",
                    finding=finding,
                    confidence=0.75,
                    label=rule_id or "MEM-09",
                )
            )
        if rule_id in {"MEM-07", "MEM-05"} and "read" in finding.title.lower():
            edges.append(
                _edge_from_finding(
                    kind=EdgeKind.READS,
                    from_node=canonical_node_id("tool", tool),
                    to_node="source:untrusted_memory",
                    finding=finding,
                    confidence=0.75,
                    label=rule_id or "MEM-07",
                )
            )
    write_tools = [
        t.name for t in server.tools if t.name in {"create_entities", "create_relations", "add_observations"}
    ]
    read_tools = [t.name for t in server.tools if t.name in {"open_nodes", "search_nodes", "read_graph"}]
    for write_tool in write_tools:
        edges.append(
            GraphEdge(
                id=f"edge-writes-memory-{write_tool}",
                kind=EdgeKind.WRITES,
                from_node=canonical_node_id("tool", write_tool),
                to_node="source:untrusted_memory",
                confidence=0.8,
                reachability=1.0,
                layer=GraphLayer.DATAFLOW,
                label="MEM-05",
            )
        )
    for write_tool in write_tools:
        for read_tool in read_tools:
            edges.append(
                GraphEdge(
                    id=f"edge-invokes-memory-{write_tool}-{read_tool}",
                    kind=EdgeKind.INVOKES,
                    from_node=canonical_node_id("tool", write_tool),
                    to_node=canonical_node_id("tool", read_tool),
                    confidence=0.55,
                    reachability=0.8,
                    layer=GraphLayer.DATAFLOW,
                    label="memory_poison_chain",
                    evidence_strength="heuristic",
                    analysis_depth="L0",
                )
            )
    for tool in server.tools:
        if tool.name in {"read_graph", "open_nodes", "search_nodes"}:
            edges.append(
                GraphEdge(
                    id=f"edge-reads-memory-{tool.name}",
                    kind=EdgeKind.READS,
                    from_node=canonical_node_id("tool", tool.name),
                    to_node="source:untrusted_memory",
                    confidence=0.7,
                    reachability=1.0,
                    layer=GraphLayer.DATAFLOW,
                    label="MEM-07",
                )
            )
    return edges


def export_read_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    """READS edges for filesystem/scoping read tools (READ_EXFIL support)."""
    edges: list[GraphEdge] = []
    staging = canonical_node_id("resource", "chain_staging")
    read_tools: list[str] = []
    egress_tools: list[str] = []
    for tool in server.tools:
        cap = tool.capability
        if not cap:
            continue
        if cap.reads_untrusted_input:
            read_tools.append(tool.name)
            edges.append(
                GraphEdge(
                    id=f"edge-reads-staging-{tool.name}",
                    kind=EdgeKind.READS,
                    from_node=canonical_node_id("tool", tool.name),
                    to_node=staging,
                    confidence=0.75,
                    reachability=1.0,
                    layer=GraphLayer.DATAFLOW,
                    label="READS",
                )
            )
        if cap.egresses_network:
            egress_tools.append(tool.name)
    for finding in findings:
        if finding.analyzer not in {"filesystem_abuse", "scoping"}:
            continue
        tool = _finding_tool(finding)
        if tool and tool not in read_tools:
            read_tools.append(tool)
            edges.append(
                _edge_from_finding(
                    kind=EdgeKind.READS,
                    from_node=canonical_node_id("tool", tool),
                    to_node=staging,
                    finding=finding,
                    confidence=0.8,
                    label=_finding_rule_id(finding),
                )
            )
    for exfil in egress_tools:
        edges.append(
            GraphEdge(
                id=f"edge-egress-{exfil}",
                kind=EdgeKind.EGRESS,
                from_node=canonical_node_id("tool", exfil),
                to_node="sink:external_network",
                confidence=0.85,
                reachability=1.0,
                layer=GraphLayer.DATAFLOW,
                label="EGRESS",
            )
        )
    return edges


def _can_chain_tools(src: MCPTool, dst: MCPTool) -> bool:
    if not src.capability or not dst.capability:
        return False
    s, d = src.capability, dst.capability
    return (
        s.reads_untrusted_input and (d.egresses_network or d.executes_commands or d.accesses_sensitive_data)
    ) or (s.accesses_sensitive_data and d.egresses_network)


def export_capability_chain_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    """Heuristic INVOKES edges between tools (legacy capability-graph parity)."""
    edges: list[GraphEdge] = []
    for src in server.tools:
        for dst in server.tools:
            if src.name == dst.name or not _can_chain_tools(src, dst):
                continue
            edges.append(
                GraphEdge(
                    id=f"edge-invokes-{src.name}-{dst.name}",
                    kind=EdgeKind.INVOKES,
                    from_node=canonical_node_id("tool", src.name),
                    to_node=canonical_node_id("tool", dst.name),
                    confidence=0.55,
                    reachability=0.75,
                    layer=GraphLayer.DATAFLOW,
                    label="capability_chain",
                    evidence_strength="heuristic",
                    analysis_depth="L0",
                )
            )
    return edges


def export_client_capability_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    sampling = canonical_node_id("capability", "sampling")
    elicitation = canonical_node_id("capability", "elicitation")
    env_tools = [
        t.name
        for t in server.tools
        if "env" in t.name.lower() or (t.capability and t.capability.accesses_sensitive_data)
    ]
    for tool_name in env_tools:
        edges.append(
            GraphEdge(
                id=f"edge-triggers-sampling-{tool_name}",
                kind=EdgeKind.TRIGGERS,
                from_node=canonical_node_id("tool", tool_name),
                to_node=sampling,
                confidence=0.7,
                reachability=0.85,
                layer=GraphLayer.TRUST_BOUNDARY,
                label="CAP-04",
                evidence_strength="heuristic",
                analysis_depth="L0",
            )
        )
    for finding in findings:
        if finding.analyzer != "transport_exposure":
            continue
        rule_id = _finding_rule_id(finding)
        if rule_id not in {"CAP-05", "CAP-06"}:
            continue
        tool = _finding_tool(finding) or "trigger-url-elicitation"
        edges.append(
            _edge_from_finding(
                kind=EdgeKind.TRIGGERS,
                from_node=canonical_node_id("tool", tool),
                to_node=elicitation,
                finding=finding,
                confidence=0.75,
                label=rule_id,
                layer=GraphLayer.TRUST_BOUNDARY,
            )
        )
    for tool in server.tools:
        if "elicitation" in tool.name.lower() or "trigger-url" in tool.name.lower():
            edges.append(
                GraphEdge(
                    id=f"edge-triggers-elicitation-{tool.name}",
                    kind=EdgeKind.TRIGGERS,
                    from_node=canonical_node_id("tool", tool.name),
                    to_node=elicitation,
                    confidence=0.7,
                    reachability=0.8,
                    layer=GraphLayer.TRUST_BOUNDARY,
                    label="CAP-05",
                    evidence_strength="heuristic",
                    analysis_depth="L0",
                )
            )
    return edges


def _finding_file(finding: Finding) -> str | None:
    if finding.location and finding.location.file:
        return finding.location.file
    evidence = finding.evidence or {}
    if file := evidence.get("file"):
        return str(file)
    for fact in evidence.get("facts") or []:
        if isinstance(fact, dict) and fact.get("file"):
            return str(fact["file"])
    code_loc = evidence.get("code_location") or {}
    if isinstance(code_loc, dict) and code_loc.get("file"):
        return str(code_loc["file"])
    return None


def _infer_git_tool(server: MCPServerInfo, findings: list[Finding]) -> str | None:
    for finding in findings:
        if finding.analyzer != "scoping":
            continue
        rule_id = _finding_rule_id(finding)
        if rule_id not in {"GIT-03", "GIT-04", "AUTH-01"}:
            continue
        tool = _finding_tool(finding)
        if tool:
            return tool
        path = (_finding_file(finding) or "").lower()
        if "/git/" in path or path.endswith("/git") or "mcp_server_git" in path:
            return "git_log"
    return None


def _infer_filesystem_tool(findings: list[Finding]) -> str | None:
    for finding in findings:
        if finding.analyzer != "sym_toctou":
            continue
        tool = _finding_tool(finding)
        if tool:
            return tool
        path = (_finding_file(finding) or "").lower()
        if "filesystem" in path or "path-validation" in path:
            return "read_file"
    return None


def export_git_read_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    git_tools: set[str] = set()
    for tool in server.tools:
        if tool.name.lower().startswith("git") or "git_" in tool.name.lower():
            git_tools.add(tool.name)
    for finding in findings:
        if finding.analyzer != "scoping":
            continue
        rule_id = _finding_rule_id(finding)
        if rule_id not in {"GIT-03", "GIT-04", "AUTH-01"}:
            continue
        tool = _finding_tool(finding)
        if tool:
            git_tools.add(tool)
    synthetic = _infer_git_tool(server, findings)
    if synthetic:
        git_tools.add(synthetic)
    for tool_name in sorted(git_tools):
        edges.append(
            GraphEdge(
                id=f"edge-reads-git-{tool_name}",
                kind=EdgeKind.READS,
                from_node=canonical_node_id("tool", tool_name),
                to_node="sink:disk",
                confidence=0.75,
                reachability=1.0,
                layer=GraphLayer.DATAFLOW,
                label="GIT-03",
            )
        )
    return edges


def export_sym_toctou_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    for finding in findings:
        if finding.analyzer != "sym_toctou":
            continue
        tool = _finding_tool(finding)
        if not tool:
            for candidate in server.tools:
                if candidate.capability and candidate.capability.reads_untrusted_input:
                    tool = candidate.name
                    break
        if not tool:
            tool = _infer_filesystem_tool([finding])
        if not tool:
            continue
        from_node = canonical_node_id("tool", tool)
        edges.append(
            _edge_from_finding(
                kind=EdgeKind.READS,
                from_node=from_node,
                to_node="sink:disk",
                finding=finding,
                confidence=0.7,
                label=_finding_rule_id(finding) or "SYM-01",
            )
        )
        edges.append(
            GraphEdge(
                id=f"edge-reads-toctou-{tool}-parallel",
                kind=EdgeKind.READS,
                from_node=from_node,
                to_node="source:parallel_read",
                confidence=0.65,
                reachability=0.8,
                layer=GraphLayer.DATAFLOW,
                label="SYM-02",
                evidence_strength="heuristic",
                analysis_depth="L0",
            )
        )
    return edges


PRODUCER_REGISTRY: dict[str, GraphEdgeExporter] = {
    "network_egress": export_network_egress_edges,
    "transport_exposure": export_transport_edges,
    "scoping": export_scoping_edges,
    "resources_abuse": export_resource_edges,
    "data_leakage": export_env_read_edges,
    "dual_surface": export_dual_surface_edges,
    "shared_memory_poisoning": export_memory_poison_edges,
    "memory_persistence": export_memory_poison_edges,
    "context_memory_implant": export_memory_poison_edges,
    "filesystem_abuse": export_read_edges,
    "read_exfil": export_read_edges,
    "sym_toctou": export_sym_toctou_edges,
    "git_reads": export_git_read_edges,
    "capability_chains": export_capability_chain_edges,
    "client_capabilities": export_client_capability_edges,
}


def export_all_edges(server: MCPServerInfo, findings: list[Finding]) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    seen_producers: set[str] = set()
    for finding in findings:
        name = finding.analyzer
        if name in PRODUCER_REGISTRY and name not in seen_producers:
            edges.extend(PRODUCER_REGISTRY[name](server, findings))
            seen_producers.add(name)
    for name, exporter in PRODUCER_REGISTRY.items():
        if name in {"read_exfil", "filesystem_abuse"}:
            continue
        if name not in seen_producers:
            edges.extend(exporter(server, findings))
            seen_producers.add(name)
    edges.extend(export_read_edges(server, findings))
    edges.extend(export_capability_chain_edges(server, findings))
    edges.extend(export_client_capability_edges(server, findings))
    edges.extend(export_git_read_edges(server, findings))
    return edges


def _cap_summary(tool: MCPTool) -> dict[str, Any]:
    cap = tool.capability
    return {
        "reads_untrusted_input": cap.reads_untrusted_input,
        "egresses_network": cap.egresses_network,
        "accesses_sensitive_data": cap.accesses_sensitive_data,
        "executes_commands": cap.executes_commands,
        "mutates_state": cap.mutates_state,
    }
