"""Policy edges and transport seeding for attack graph v3."""

from __future__ import annotations

from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding
from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, GraphLayer, NodeKind, canonical_node_id, parse_node_id

DEFAULT_RESOURCE_ACCESS_PROBABILITY = 0.3


def _http_without_auth(findings: list[Finding]) -> bool:
    for finding in findings:
        if finding.analyzer != "transport_exposure":
            continue
        evidence = finding.evidence or {}
        rule_id = str(evidence.get("rule_id") or "")
        for fact in evidence.get("facts") or []:
            if isinstance(fact, dict) and fact.get("rule_id"):
                rule_id = str(fact["rule_id"])
        if rule_id in {"CAP-01", "CAP-02"}:
            return True
    return False


def _auth_middleware_present(findings: list[Finding]) -> bool:
    for finding in findings:
        if finding.analyzer != "transport_exposure":
            continue
        title = (finding.title or "").lower()
        if "auth" in title and "middleware" in title:
            return True
        if (finding.evidence or {}).get("auth_present"):
            return True
    return False


def seed_server_surfaces(graph: AttackGraph, server: MCPServerInfo) -> None:
    for tool in server.tools:
        cap = tool.capability
        graph.add_node(
            NodeKind.TOOL,
            tool.name,
            label=tool.name,
            metadata={
                "source_file": tool.source_file,
                "capabilities": list(
                    filter(
                        None,
                        [
                            "reads_untrusted_input" if cap and cap.reads_untrusted_input else None,
                            "egresses_network" if cap and cap.egresses_network else None,
                            "accesses_sensitive_data" if cap and cap.accesses_sensitive_data else None,
                        ],
                    )
                ),
            },
        )
    for prompt in server.prompts:
        graph.add_node(NodeKind.PROMPT, prompt.name, label=prompt.name)
    for resource in server.resources:
        uri = resource.uri or resource.name
        graph.add_node(NodeKind.RESOURCE, uri, label=resource.name or uri)
    for transport in ("http", "sse", "stdio"):
        graph.add_node(NodeKind.TRANSPORT, transport, label=transport, layer=GraphLayer.TRANSPORT)
    for capability in ("sampling", "elicitation", "roots", "tasks", "logging"):
        graph.add_node(NodeKind.CAPABILITY, capability, label=capability)


def _seed_resource_nodes_from_writes(graph: AttackGraph) -> None:
    """Ensure resource nodes exist for WRITES targets (static scans lack live resources)."""
    for edge in graph.edges.values():
        if edge.kind != EdgeKind.WRITES:
            continue
        if not edge.to_node.startswith("resource:"):
            continue
        _, local = parse_node_id(edge.to_node)
        if edge.to_node not in graph.nodes:
            graph.add_node(NodeKind.RESOURCE, local, label=local)


def apply_policy_edges(graph: AttackGraph, server: MCPServerInfo, findings: list[Finding]) -> None:
    _seed_resource_nodes_from_writes(graph)
    for tool in graph.nodes_of_kind(NodeKind.TOOL):
        graph.add_edge(
            EdgeKind.DELIVERS_TO_CONTEXT,
            tool.id,
            "sink:model_context",
            confidence=1.0,
            reachability=1.0,
            policy=True,
            layer=GraphLayer.TRUST_BOUNDARY,
            evidence_strength="heuristic",
            analysis_depth="L0",
        )
    for prompt in graph.nodes_of_kind(NodeKind.PROMPT):
        graph.add_edge(
            EdgeKind.DELIVERS_TO_CONTEXT,
            prompt.id,
            "sink:model_context",
            confidence=1.0,
            reachability=1.0,
            policy=True,
            layer=GraphLayer.TRUST_BOUNDARY,
            evidence_strength="heuristic",
            analysis_depth="L0",
        )
    for resource in graph.nodes_of_kind(NodeKind.RESOURCE):
        graph.add_edge(
            EdgeKind.RESOURCE_READABLE_BY_CONTEXT,
            resource.id,
            "sink:model_context",
            confidence=1.0,
            reachability=DEFAULT_RESOURCE_ACCESS_PROBABILITY,
            access_probability=DEFAULT_RESOURCE_ACCESS_PROBABILITY,
            policy=True,
            layer=GraphLayer.TRUST_BOUNDARY,
            evidence_strength="heuristic",
            analysis_depth="L0",
        )
    if graph.has_capability("sampling"):
        graph.add_edge(
            EdgeKind.DELIVERS_TO_CLIENT_LLM,
            canonical_node_id(NodeKind.CAPABILITY, "sampling"),
            "sink:client_llm",
            confidence=1.0,
            reachability=1.0,
            policy=True,
            layer=GraphLayer.TRUST_BOUNDARY,
            evidence_strength="heuristic",
            analysis_depth="L0",
        )
    if _http_without_auth(findings):
        transport = canonical_node_id(NodeKind.TRANSPORT, "http")
        for tool in graph.nodes_of_kind(NodeKind.TOOL):
            graph.add_edge(
                EdgeKind.EXPOSES,
                transport,
                tool.id,
                confidence=0.9 if not _auth_middleware_present(findings) else 0.4,
                reachability=0.9,
                layer=GraphLayer.TRANSPORT,
                label="CAP-01",
            )
        if _auth_middleware_present(findings):
            graph.add_edge(
                EdgeKind.GUARDS,
                "control:bearer_auth",
                transport,
                confidence=0.9,
                reachability=1.0,
                layer=GraphLayer.TRANSPORT,
                label="auth_middleware",
            )
            graph.ensure_node("control:bearer_auth", kind=NodeKind.CONTROL)
