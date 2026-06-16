"""Attack graph v3 container — nodes, edges, indexes, serialization."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from mcts.reporting.models import Finding, Severity
from mcts.scoring.attack_graph_defaults import apply_node_defaults, seed_sink_node, seed_source_node
from mcts.scoring.attack_graph_models import (
    SINK_NAMES,
    SOURCE_NAMES,
    EdgeKind,
    EvidenceStrength,
    GraphEdge,
    GraphLayer,
    GraphNode,
    GraphPath,
    MatchedChain,
    NodeKind,
    _edge_id,
    canonical_node_id,
    parse_node_id,
)
from mcts.scoring.evidence_tags import tag_attack_chain_finding


def _edge_key(kind: EdgeKind, from_node: str, to_node: str) -> tuple[str, str, str]:
    return (kind.value, from_node, to_node)


class AttackGraph:
    """In-memory attack graph with typed edges and layer filtering."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._edges_by_kind: dict[EdgeKind, list[str]] = {}
        self._outgoing: dict[str, list[str]] = {}
        self._nodes_with_outgoing_kind: dict[EdgeKind, set[str]] = {}
        self.matched_chains: list[MatchedChain] = []
        self.total_risk_score: float = 0.0

    @property
    def nodes(self) -> dict[str, GraphNode]:
        return self._nodes

    @property
    def edges(self) -> dict[str, GraphEdge]:
        return self._edges

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def trust(self, node_id: str) -> str:
        node = self._nodes.get(node_id)
        return node.trust.value if node else "semi_trusted"

    def sensitivity(self, node_id: str) -> str:
        node = self._nodes.get(node_id)
        return node.sensitivity.value if node else "medium"

    def add_node(
        self,
        kind: NodeKind | str,
        local_id: str,
        *,
        label: str | None = None,
        layer: GraphLayer | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> GraphNode:
        kind_enum = NodeKind(kind) if isinstance(kind, str) else kind
        node = GraphNode.synthetic(
            kind_enum,
            local_id,
            label=label,
            layer=layer,
            metadata=metadata,
        )
        node = apply_node_defaults(node)
        self._nodes[node.id] = node
        return node

    def ensure_node(self, node_id: str, *, kind: NodeKind | None = None) -> GraphNode:
        if node_id in self._nodes:
            return self._nodes[node_id]
        parsed_kind, local = parse_node_id(node_id)
        kind_enum = kind or NodeKind(parsed_kind)
        return self.add_node(kind_enum, local)

    def seed_sources_and_sinks(self) -> None:
        for name in SOURCE_NAMES:
            node = seed_source_node(name)
            self._nodes[node.id] = node
        for name in SINK_NAMES:
            node = seed_sink_node(name)
            self._nodes[node.id] = node

    def nodes_of_kind(self, kind: NodeKind) -> list[GraphNode]:
        return [n for n in self._nodes.values() if n.kind == kind]

    def has_capability(self, name: str) -> bool:
        return canonical_node_id(NodeKind.CAPABILITY, name) in self._nodes

    def add_edge(
        self,
        kind: EdgeKind | str,
        from_node: str,
        to_node: str,
        *,
        confidence: float = 0.7,
        reachability: float = 1.0,
        access_probability: float | None = None,
        label: str = "",
        layer: GraphLayer | None = None,
        policy: bool = False,
        evidence_strength: EvidenceStrength | str = EvidenceStrength.STATIC,
        analysis_depth: str = "L1",
        evidence: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> GraphEdge:
        kind_enum = EdgeKind(kind) if isinstance(kind, str) else kind
        self.ensure_node(from_node)
        self.ensure_node(to_node)
        edge = GraphEdge(
            id=_edge_id(kind_enum, from_node, to_node),
            kind=kind_enum,
            from_node=from_node,
            to_node=to_node,
            label=label,
            confidence=confidence,
            reachability=reachability,
            access_probability=access_probability,
            layer=layer or GraphLayer.DATAFLOW,
            policy=policy,
            evidence_strength=(
                evidence_strength
                if isinstance(evidence_strength, EvidenceStrength)
                else EvidenceStrength(evidence_strength)
            ),
            analysis_depth=analysis_depth,
            metadata=dict(metadata or {}),
        )
        if evidence:
            from mcts.scoring.attack_graph_models import EdgeEvidence

            edge.evidence.extend(EdgeEvidence.model_validate(e) for e in evidence)
        return self._store_edge(edge)

    def merge_edge(self, edge: GraphEdge) -> GraphEdge:
        self.ensure_node(edge.from_node)
        self.ensure_node(edge.to_node)
        key = _edge_key(edge.kind, edge.from_node, edge.to_node)
        existing_id = next(
            (
                eid
                for eid in self._edges_by_kind.get(edge.kind, [])
                if _edge_key(self._edges[eid].kind, self._edges[eid].from_node, self._edges[eid].to_node)
                == key
            ),
            None,
        )
        if existing_id:
            stored = self._edges[existing_id]
            stored.merge_from(edge)
            return stored
        return self._store_edge(edge)

    def _store_edge(self, edge: GraphEdge) -> GraphEdge:
        self._edges[edge.id] = edge
        self._edges_by_kind.setdefault(edge.kind, [])
        if edge.id not in self._edges_by_kind[edge.kind]:
            self._edges_by_kind[edge.kind].append(edge.id)
        self._outgoing.setdefault(edge.from_node, [])
        if edge.id not in self._outgoing[edge.from_node]:
            self._outgoing[edge.from_node].append(edge.id)
        self._nodes_with_outgoing_kind.setdefault(edge.kind, set()).add(edge.from_node)
        return edge

    def out_edges(self, node_id: str) -> list[GraphEdge]:
        return [self._edges[eid] for eid in self._outgoing.get(node_id, []) if eid in self._edges]

    def edges_of_kind(self, kind: EdgeKind) -> list[GraphEdge]:
        return [self._edges[eid] for eid in self._edges_by_kind.get(kind, []) if eid in self._edges]

    def nodes_with_outgoing(self, kind: EdgeKind) -> set[str]:
        return set(self._nodes_with_outgoing_kind.get(kind, set()))

    def filter_layers(self, layers: Iterable[GraphLayer | str]) -> AttackGraph:
        allowed = {GraphLayer(layer) if isinstance(layer, str) else layer for layer in layers}
        filtered = AttackGraph()
        filtered._nodes = dict(self._nodes)
        for edge in self._edges.values():
            if edge.layer in allowed or edge.policy:
                filtered.merge_edge(edge.model_copy())
        filtered.matched_chains = list(self.matched_chains)
        filtered.total_risk_score = self.total_risk_score
        return filtered

    def to_report_dict(self) -> dict[str, Any]:
        node_layers = {n.layer.value for n in self._nodes.values()}
        edge_layers = {e.layer.value for e in self._edges.values()}
        layers_present = sorted(node_layers | edge_layers)
        paths = [self._path_to_dict(chain) for chain in self.matched_chains]
        return {
            "version": 3,
            "nodes": [n.model_dump(mode="json") for n in self._nodes.values()],
            "edges": [e.model_dump(mode="json") for e in self._edges.values()],
            "paths": paths,
            "templates_matched": [c.template_id for c in self.matched_chains],
            "total_risk_score": round(self.total_risk_score, 2),
            "layers_present": layers_present,
        }

    def _path_to_dict(self, chain: MatchedChain) -> dict[str, Any]:
        path = chain.path
        return {
            "id": f"path-{chain.template_id}-{hash(tuple(path.nodes)) & 0xFFFF}",
            "template_id": chain.template_id,
            "nodes": path.nodes,
            "edges": [e.id for e in path.edges],
            "tools_on_path": path.tool_names_on_path(),
            "hop_count": path.hop_count,
            "chain_confidence": round(chain.path_confidence, 3),
            "path_reachability": round(chain.path_reachability, 3),
            "chain_risk_score": round(chain.chain_risk_score, 3),
            "trust_boundary_crossings": chain.trust_boundary_crossings,
            "explanation": [s.model_dump(mode="json") for s in chain.explanation],
            "finding_ids": [
                chain.legacy_finding_id or f"chain-{chain.template_id.lower().replace('_', '-')}"
            ],
        }

    def to_findings(self) -> list[Finding]:
        from mcts.scoring.graph_explain import matched_chain_to_finding

        by_template: dict[str, list[MatchedChain]] = {}
        for chain in self.matched_chains:
            by_template.setdefault(chain.template_id, []).append(chain)
        findings: list[Finding] = []
        for template_id, chains in by_template.items():
            ranked = sorted(chains, key=lambda c: c.chain_risk_score, reverse=True)[:3]
            finding = matched_chain_to_finding(template_id, ranked)
            if finding:
                findings.append(tag_attack_chain_finding(finding))
        return findings


def build_path_from_edges(start: str, edges: list[GraphEdge]) -> GraphPath:
    nodes = [start]
    for edge in edges:
        nodes.append(edge.to_node)
    return GraphPath(nodes=nodes, edges=edges, end=edges[-1].to_node if edges else start)


def severity_from_template(severity: str) -> Severity:
    try:
        return Severity(severity.lower())
    except ValueError:
        return Severity.HIGH
