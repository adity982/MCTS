"""Tests for attack graph v3 model and container."""

from __future__ import annotations

from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, NodeKind, canonical_node_id


def test_node_id_canonical() -> None:
    assert canonical_node_id(NodeKind.TOOL, "fetch") == "tool:fetch"
    assert canonical_node_id("tool", "tool:fetch") == "tool:fetch"


def test_add_edge_rebuilds_indexes() -> None:
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TOOL, "fetch")
    graph.add_edge(EdgeKind.EGRESS, "tool:fetch", "sink:external_network", confidence=0.8)
    assert graph.nodes_with_outgoing(EdgeKind.EGRESS) == {"tool:fetch"}
    assert len(graph.out_edges("tool:fetch")) == 1


def test_merge_edge_confidence_max() -> None:
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TOOL, "fetch")
    first = graph.add_edge(EdgeKind.EGRESS, "tool:fetch", "sink:external_network", confidence=0.7)
    second = graph.add_edge(EdgeKind.EGRESS, "tool:fetch", "sink:external_network", confidence=0.9)
    graph.merge_edge(second)
    merged = graph.edges[first.id]
    assert merged.confidence == 0.9
    assert len(graph.edges) == 1


def test_to_report_dict_version_3() -> None:
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TOOL, "fetch")
    graph.add_edge(EdgeKind.EGRESS, "tool:fetch", "sink:external_network")
    graph.add_edge(EdgeKind.DELIVERS_TO_CONTEXT, "tool:fetch", "sink:model_context", policy=True)
    report = graph.to_report_dict()
    assert report["version"] == 3
    assert any(node["id"] == "tool:fetch" for node in report["nodes"])
    assert report["edges"]
