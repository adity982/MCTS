"""Phase 3c graph polish: fixes registry, counterfactuals, compression, UI."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_builder import GraphBuilder
from mcts.scoring.attack_graph_models import EdgeKind, GraphEdge, GraphLayer, NodeKind
from mcts.scoring.graph_compress import compress_paths
from mcts.scoring.graph_counterfactual import counterfactual_for_chain
from mcts.scoring.graph_fixes import describe_fixes, load_fixes_registry
from mcts.scoring.graph_ui import normalize_attack_graph_for_ui


def test_fixes_registry_loads() -> None:
    registry = load_fixes_registry()
    assert "add_http_auth" in registry
    assert "remove_env_tool" in registry


def test_describe_fixes_uses_registry() -> None:
    fixes = describe_fixes(["add_http_auth", "unknown_fix_kind"])
    assert fixes[0]["description"]
    assert fixes[1]["kind"] == "unknown_fix_kind"


def test_counterfactual_for_chain() -> None:
    payload = counterfactual_for_chain("HTTP_TAKEOVER", ["get-env"])
    assert payload["template_id"] == "HTTP_TAKEOVER"
    assert payload["actions"]
    assert payload["recommended_fixes"]


def test_apply_fix_kind_remove_env_tool() -> None:
    from mcts.scoring.attack_graph_models import EdgeKind, NodeKind
    from mcts.scoring.graph_mutate import apply_fix_kind

    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TOOL, "get-env", label="get-env")
    graph.add_edge(EdgeKind.READS, "tool:get-env", "sink:env")
    mutated = apply_fix_kind(graph, "remove_env_tool")
    assert "tool:get-env" not in mutated.nodes
    assert not any(edge.from_node == "tool:get-env" for edge in mutated.edges.values())


def test_simulate_remove_env_tool_eliminates_http_takeover() -> None:
    from mcts.scoring.attack_graph_models import EdgeKind, GraphLayer, NodeKind
    from mcts.scoring.graph_mutate import simulate_fix_eliminates_template
    from mcts.scoring.graph_templates import load_chain_templates

    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TRANSPORT, "http", label="http", layer=GraphLayer.TRANSPORT)
    graph.add_node(NodeKind.TOOL, "get-env", label="get-env")
    graph.add_edge(
        EdgeKind.EXPOSES,
        "transport:http",
        "tool:get-env",
        layer=GraphLayer.TRANSPORT,
        reachability=1.0,
    )
    graph.add_edge(EdgeKind.READS, "tool:get-env", "sink:env", reachability=1.0)
    graph.add_edge(
        EdgeKind.DELIVERS_TO_CONTEXT,
        "tool:get-env",
        "sink:model_context",
        reachability=1.0,
    )
    template = next(t for t in load_chain_templates() if t.id == "HTTP_TAKEOVER")
    assert simulate_fix_eliminates_template(graph, template, "remove_env_tool")
    assert simulate_fix_eliminates_template(graph, template, "disable_http_transport")


def test_inventory_layer_adds_cross_server_edges() -> None:
    from mcts.inventory.models import InventoryEntry
    from mcts.scoring.attack_graph_models import GraphLayer
    from mcts.scoring.graph_inventory import attach_inventory_layer

    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    inventory = [
        InventoryEntry(
            client="cursor",
            config_path="/a",
            server_name="reader",
            tools=["read_file"],
        ),
        InventoryEntry(
            client="cursor",
            config_path="/b",
            server_name="writer",
            tools=["write_file"],
        ),
    ]
    attach_inventory_layer(graph, inventory)
    inventory_edges = [edge for edge in graph.edges.values() if edge.layer == GraphLayer.INVENTORY]
    assert inventory_edges
    assert any(edge.label == "cross_server_read_write" for edge in inventory_edges)


def test_counterfactual_includes_fix_simulation() -> None:
    from mcts.scoring.attack_graph_models import EdgeKind, GraphLayer, NodeKind
    from mcts.scoring.graph_mutate import clone_graph

    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TRANSPORT, "http", label="http", layer=GraphLayer.TRANSPORT)
    graph.add_node(NodeKind.TOOL, "get-env", label="get-env")
    graph.add_edge(
        EdgeKind.EXPOSES,
        "transport:http",
        "tool:get-env",
        layer=GraphLayer.TRANSPORT,
        reachability=1.0,
    )
    graph.add_edge(EdgeKind.READS, "tool:get-env", "sink:env", reachability=1.0)
    graph.add_edge(
        EdgeKind.DELIVERS_TO_CONTEXT,
        "tool:get-env",
        "sink:model_context",
        reachability=1.0,
    )
    payload = counterfactual_for_chain("HTTP_TAKEOVER", ["get-env"], graph=clone_graph(graph))
    assert payload.get("fix_simulation")
    assert "remove_env_tool" in payload.get("effective_fixes", [])


def test_config_counterfactuals_and_compress_default_on() -> None:
    config = ScanConfig(target=".")
    assert config.attack_graph_enable_counterfactuals is True
    assert config.attack_graph_compress_for_ui is True


def test_compress_paths_dedupes() -> None:
    paths = [
        {"template_id": "A", "tools_on_path": ["t1"], "chain_risk_score": 1},
        {"template_id": "A", "tools_on_path": ["t1"], "chain_risk_score": 2},
        {"template_id": "B", "tools_on_path": ["t2"], "chain_risk_score": 5},
    ]
    compressed, stats = compress_paths(paths, max_total=2, max_per_template=1)
    assert len(compressed) == 2
    assert stats["dropped"] == 1


def test_graph_builder_attaches_recommended_fixes() -> None:
    graph = AttackGraph()
    graph.seed_sources_and_sinks()
    graph.add_node(NodeKind.TOOL, "trigger-url-elicitation", label="trigger-url-elicitation")
    graph.add_node(NodeKind.CAPABILITY, "elicitation", label="elicitation")
    graph.merge_edge(
        GraphEdge(
            id="edge-elicit",
            kind=EdgeKind.TRIGGERS,
            from_node="tool:trigger-url-elicitation",
            to_node="capability:elicitation",
            layer=GraphLayer.TRUST_BOUNDARY,
            confidence=0.75,
            reachability=0.8,
        )
    )
    from mcts.mcp.models import MCPServerInfo, MCPTool

    server = MCPServerInfo(
        name="demo",
        tools=[MCPTool(name="trigger-url-elicitation", description="elicitation tool")],
    )
    builder = GraphBuilder(config=ScanConfig(target=".", attack_graph_enable_counterfactuals=True))
    built = builder.build(server, [])
    elicit = next((c for c in built.matched_chains if c.template_id == "ELICIT_PHISH"), None)
    assert elicit is not None
    assert elicit.recommended_fixes
    assert elicit.counterfactual_remediation


def test_to_report_dict_compresses_when_requested() -> None:
    graph = AttackGraph()
    graph.matched_chains = []
    report = graph.to_report_dict(compress_for_ui=True)
    assert report.get("compression_stats") is not None


def test_normalize_ui_includes_layers_and_edge_class() -> None:
    raw = {
        "version": 3,
        "nodes": [
            {
                "id": "tool:fetch",
                "kind": "tool",
                "label": "fetch",
                "layer": "mcp_surface",
                "trust": "semi_trusted",
                "sensitivity": "medium",
            }
        ],
        "edges": [
            {
                "from_node": "tool:fetch",
                "to_node": "sink:external_network",
                "kind": "EGRESS",
                "layer": "dataflow",
                "policy": False,
                "evidence_strength": "static",
            }
        ],
        "paths": [],
        "layers_present": ["dataflow", "mcp_surface"],
    }
    ui = normalize_attack_graph_for_ui(raw)
    assert ui["nodes"][0]["trust"] == "semi_trusted"
    assert ui["edges"][0]["edge_class"] == "proven"
    assert "dataflow" in ui["layers_present"]


def test_suggest_fixes_from_report(tmp_path) -> None:
    from mcts.scoring.graph_suggest import suggest_fixes_from_report

    report = {
        "attack_graph": {
            "templates_matched": ["ELICIT_PHISH", "ELICIT_PHISH"],
        }
    }
    path = tmp_path / "scan.json"
    path.write_text(__import__("json").dumps(report), encoding="utf-8")
    rows = suggest_fixes_from_report(path)
    assert len(rows) == 1
    assert rows[0]["template_id"] == "ELICIT_PHISH"


def test_scanner_counterfactual_flag() -> None:
    target = "tests/fixtures/monorepo-mini/src/everything/tools/trigger-url-elicitation.ts"
    report = Scanner(
        ScanConfig(
            target=target,
            surface_depth="full",
            attack_graph_enable_counterfactuals=True,
        )
    ).run()
    chain = next(
        f
        for f in report.findings
        if f.analyzer == "attack_graph" and f.evidence.get("template_id") == "ELICIT_PHISH"
    )
    assert chain.evidence.get("counterfactual_remediation")
