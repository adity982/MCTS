"""SSRF_RESOURCE template and resource-node seeding tests."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, GraphEdge, GraphLayer
from mcts.scoring.attack_graph_policy import apply_policy_edges
from mcts.scoring.graph_matcher import match_template
from mcts.scoring.graph_templates import load_template, load_templates

MONOREPO_MINI = Path("tests/fixtures/monorepo-mini")
REGRESSION = Path("tests/fixtures/regression")


def test_merge_edge_ensures_endpoint_nodes() -> None:
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.merge_edge(
        GraphEdge(
            id="edge-prompt-egress",
            kind=EdgeKind.EGRESS,
            from_node="prompt:fetch",
            to_node="sink:external_network",
            layer=GraphLayer.DATAFLOW,
        )
    )
    assert graph.get_node("prompt:fetch") is not None
    assert graph.get_node("sink:external_network") is not None


def test_resource_nodes_seeded_from_writes() -> None:
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.merge_edge(
        GraphEdge(
            id="edge-write-resource",
            kind=EdgeKind.WRITES,
            from_node="tool:gzip-file-as-resource",
            to_node="resource:session/staged",
            layer=GraphLayer.DATAFLOW,
        )
    )
    apply_policy_edges(graph, __import__("mcts.mcp.models", fromlist=["MCPServerInfo"]).MCPServerInfo(), [])
    assert graph.get_node("resource:session/staged") is not None
    readable = [e for e in graph.edges.values() if e.kind == EdgeKind.RESOURCE_READABLE_BY_CONTEXT]
    assert readable
    assert readable[0].to_node == "sink:model_context"


def test_ssrf_resource_matches_r15_fixture() -> None:
    spec = json.loads((REGRESSION / "R-15-gzip-resource" / "expected.json").read_text())
    target = MONOREPO_MINI / spec["servers_path"]
    report = Scanner(ScanConfig(target=str(target), surface_depth="full")).run()
    matched = set(report.attack_graph.get("templates_matched") or [])
    assert "SSRF_RESOURCE" in matched


def test_all_templates_validate() -> None:
    templates = load_templates()
    assert len(templates) == 12
    ssrf = load_template(
        __import__("mcts.scoring.graph_templates", fromlist=["TEMPLATES_DIR"]).TEMPLATES_DIR
        / "SSRF_RESOURCE.yaml"
    )
    assert ssrf.id == "SSRF_RESOURCE"
    assert ssrf.edge_pattern[1].to_kind == "resource"


def test_ssrf_resource_requires_resource_readable_edge() -> None:
    """WRITES + policy resource node enables SSRF_RESOURCE matching."""
    from mcts.mcp.models import MCPServerInfo

    template = next(t for t in load_templates() if t.id == "SSRF_RESOURCE")
    minimal = AttackGraph()
    minimal.seed_sources_and_sinks()
    minimal.merge_edge(
        GraphEdge(
            id="e1",
            kind=EdgeKind.EGRESS,
            from_node="tool:gzip-file-as-resource",
            to_node="sink:external_network",
            layer=GraphLayer.DATAFLOW,
        )
    )
    minimal.merge_edge(
        GraphEdge(
            id="e2",
            kind=EdgeKind.WRITES,
            from_node="tool:gzip-file-as-resource",
            to_node="resource:session/staged",
            layer=GraphLayer.DATAFLOW,
        )
    )
    apply_policy_edges(minimal, MCPServerInfo(), [])
    matches = match_template(template, minimal)
    assert matches
    assert matches[0].path.hop_count >= 2
