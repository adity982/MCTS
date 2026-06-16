"""Default trust and sensitivity seeding for attack graph nodes."""

from __future__ import annotations

from mcts.scoring.attack_graph_models import (
    GraphNode,
    NodeKind,
    SensitivityLevel,
    TrustLevel,
    canonical_node_id,
)


def default_trust(kind: NodeKind, local_id: str) -> TrustLevel:
    if kind == NodeKind.SOURCE:
        return TrustLevel.UNTRUSTED
    if kind == NodeKind.SINK:
        if local_id == "client_llm":
            return TrustLevel.EXTERNAL
        if local_id in {"external_network"}:
            return TrustLevel.UNTRUSTED
        return TrustLevel.TRUSTED
    if kind == NodeKind.TRANSPORT:
        return TrustLevel.UNTRUSTED
    return TrustLevel.SEMI_TRUSTED


def default_sensitivity(kind: NodeKind, local_id: str) -> SensitivityLevel:
    if kind == NodeKind.SINK:
        if local_id == "env":
            return SensitivityLevel.CRITICAL
        if local_id in {"disk", "cross_session", "client_llm"}:
            return SensitivityLevel.HIGH
        if local_id == "external_network":
            return SensitivityLevel.MEDIUM
        return SensitivityLevel.MEDIUM
    if kind == NodeKind.SOURCE:
        return SensitivityLevel.LOW
    if kind == NodeKind.TRANSPORT:
        return SensitivityLevel.HIGH
    return SensitivityLevel.MEDIUM


def apply_node_defaults(node: GraphNode) -> GraphNode:
    """Fill trust/sensitivity when still at generic defaults."""
    _, local = node.id.split(":", 1) if ":" in node.id else ("tool", node.id)
    trust = default_trust(node.kind, local)
    sensitivity = default_sensitivity(node.kind, local)
    updates: dict[str, object] = {}
    if node.trust == TrustLevel.SEMI_TRUSTED and trust != TrustLevel.SEMI_TRUSTED:
        updates["trust"] = trust
    if node.sensitivity == SensitivityLevel.MEDIUM and sensitivity != SensitivityLevel.MEDIUM:
        updates["sensitivity"] = sensitivity
    if updates:
        return node.model_copy(update=updates)
    return node


def seed_source_node(name: str) -> GraphNode:
    return apply_node_defaults(
        GraphNode.synthetic(
            NodeKind.SOURCE,
            name,
            trust=default_trust(NodeKind.SOURCE, name),
            sensitivity=default_sensitivity(NodeKind.SOURCE, name),
        )
    )


def seed_sink_node(name: str) -> GraphNode:
    return apply_node_defaults(
        GraphNode.synthetic(
            NodeKind.SINK,
            name,
            trust=default_trust(NodeKind.SINK, name),
            sensitivity=default_sensitivity(NodeKind.SINK, name),
        )
    )


def seed_transport_node(name: str) -> GraphNode:
    node_id = canonical_node_id(NodeKind.TRANSPORT, name)
    return apply_node_defaults(
        GraphNode(
            id=node_id,
            kind=NodeKind.TRANSPORT,
            label=name,
            trust=TrustLevel.UNTRUSTED,
            sensitivity=SensitivityLevel.HIGH,
        )
    )
