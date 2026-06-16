"""Explanation and finding emission tests."""

from __future__ import annotations

from mcts.scoring.attack_graph import AttackGraph, build_path_from_edges
from mcts.scoring.attack_graph_models import EdgeKind, MatchedChain
from mcts.scoring.graph_explain import generate_explanation, matched_chain_to_finding
from mcts.scoring.graph_templates import TEMPLATES_DIR, load_template


def test_generate_explanation_uses_template_steps() -> None:
    graph = AttackGraph()
    template = load_template(TEMPLATES_DIR / "SSRF_EXFIL.yaml")
    e1 = graph.add_edge(EdgeKind.EGRESS, "tool:fetch", "sink:external_network")
    e2 = graph.add_edge(EdgeKind.DELIVERS_TO_CONTEXT, "tool:fetch", "sink:model_context", policy=True)
    path = build_path_from_edges("tool:fetch", [e1, e2])
    steps = generate_explanation(path, template, graph)
    assert steps
    assert "network" in steps[0].message.lower()


def test_matched_chain_to_finding_emits_attack_graph_analyzer() -> None:
    graph = AttackGraph()
    template = load_template(TEMPLATES_DIR / "HTTP_TAKEOVER.yaml")
    e1 = graph.add_edge(EdgeKind.EXPOSES, "transport:http", "tool:get-env")
    e2 = graph.add_edge(EdgeKind.READS, "tool:get-env", "sink:env")
    e3 = graph.add_edge(EdgeKind.DELIVERS_TO_CONTEXT, "tool:get-env", "sink:model_context", policy=True)
    path = build_path_from_edges("transport:http", [e1, e2, e3])
    chain = MatchedChain(
        template_id="HTTP_TAKEOVER",
        path=path,
        path_confidence=0.85,
        path_reachability=0.9,
        chain_risk_score=5.0,
        explanation=generate_explanation(path, template, graph),
    )
    finding = matched_chain_to_finding("HTTP_TAKEOVER", [chain])
    assert finding is not None
    assert finding.analyzer == "attack_graph"
    assert finding.evidence.get("template_id") == "HTTP_TAKEOVER"
