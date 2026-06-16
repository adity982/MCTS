"""Graph matcher tests including HTTP_TAKEOVER golden path."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, NodeKind
from mcts.scoring.graph_matcher import match_template, path_satisfies_pattern
from mcts.scoring.graph_templates import TEMPLATES_DIR, EdgePattern, load_template

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "attack_graph"


def _load_minimal_http_takeover_graph() -> AttackGraph:
    payload = json.loads((_FIXTURES / "minimal_http_takeover.json").read_text(encoding="utf-8"))
    graph = AttackGraph()
    for node in payload["nodes"]:
        kind = NodeKind(node["kind"])
        local_id = node["id"].split(":", 1)[1]
        graph.add_node(kind, local_id, label=node.get("label", local_id))
    for edge in payload["edges"]:
        graph.add_edge(
            EdgeKind(edge["kind"]),
            edge["from"],
            edge["to"],
            confidence=edge.get("confidence", 0.9),
            reachability=edge.get("reachability", 1.0),
            policy=edge.get("policy", False),
        )
    return graph


def test_path_satisfies_http_takeover_pattern() -> None:
    graph = _load_minimal_http_takeover_graph()
    template = load_template(TEMPLATES_DIR / "HTTP_TAKEOVER.yaml")
    matches = match_template(template, graph)
    assert matches
    assert matches[0].template_id == "HTTP_TAKEOVER"


def test_path_satisfies_consecutive_pattern() -> None:
    from mcts.scoring.attack_graph import build_path_from_edges

    graph = AttackGraph()
    e1 = graph.add_edge(EdgeKind.READS, "tool:read", "resource:chain_staging")
    e2 = graph.add_edge(EdgeKind.EGRESS, "tool:read", "sink:external_network")
    path = build_path_from_edges("tool:read", [e1, e2])
    patterns = [EdgePattern(kind="READS"), EdgePattern(kind="EGRESS")]
    assert path_satisfies_pattern(path, patterns)


def test_memory_read_stays_on_tool_for_delivers() -> None:
    graph = AttackGraph()
    graph.add_edge(EdgeKind.WRITES, "tool:create_entities", "sink:cross_session")
    graph.add_edge(EdgeKind.INVOKES, "tool:create_entities", "tool:open_nodes")
    graph.add_edge(EdgeKind.READS, "tool:open_nodes", "source:untrusted_memory")
    graph.add_edge(
        EdgeKind.DELIVERS_TO_CONTEXT,
        "tool:open_nodes",
        "sink:model_context",
        policy=True,
        layer="trust_boundary",
    )
    template = load_template(TEMPLATES_DIR / "MEMORY_POISON.yaml")
    matches = match_template(template, graph)
    assert matches
    kinds = [edge.kind.value for edge in matches[0].path.edges]
    assert "READS" in kinds
    assert "DELIVERS_TO_CONTEXT" in kinds
