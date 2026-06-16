"""Risk scoring tests for attack graph paths."""

from __future__ import annotations

from mcts.scoring.attack_graph import AttackGraph, build_path_from_edges
from mcts.scoring.attack_graph_models import EdgeKind, NodeKind
from mcts.scoring.graph_risk import (
    chain_risk_score,
    geometric_mean,
    path_confidence,
    path_reachability,
    trust_multiplier,
)
from mcts.scoring.graph_templates import TEMPLATES_DIR, load_template


def test_geometric_mean_confidence() -> None:
    assert round(geometric_mean([0.95, 0.95, 0.6]), 2) == 0.82


def test_path_confidence_and_reachability_separate() -> None:
    graph = AttackGraph()
    e1 = graph.add_edge(
        EdgeKind.EGRESS,
        "tool:fetch",
        "sink:external_network",
        confidence=0.95,
        reachability=1.0,
    )
    e2 = graph.add_edge(
        EdgeKind.DELIVERS_TO_CONTEXT,
        "tool:fetch",
        "sink:model_context",
        confidence=0.95,
        reachability=0.3,
        policy=True,
    )
    path = build_path_from_edges("tool:fetch", [e1, e2])
    assert path_confidence(path) > 0.9
    assert path_reachability(path) < 0.7


def test_chain_risk_score_positive() -> None:
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TOOL, "fetch")
    e1 = graph.add_edge(EdgeKind.EGRESS, "tool:fetch", "sink:external_network", confidence=0.9)
    e2 = graph.add_edge(EdgeKind.DELIVERS_TO_CONTEXT, "tool:fetch", "sink:model_context", confidence=1.0)
    path = build_path_from_edges("tool:fetch", [e1, e2])
    template = load_template(TEMPLATES_DIR / "SSRF_EXFIL.yaml")
    score = chain_risk_score(template, path, graph)
    assert score > 0
    assert trust_multiplier(2) == 1.2
