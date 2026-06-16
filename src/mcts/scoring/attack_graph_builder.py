"""Build attack graph v3 from server surfaces and analyzer findings."""

from __future__ import annotations

from mcts.core.config import ScanConfig
from mcts.mcp.models import MCPServerInfo
from mcts.reporting.models import Finding
from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, canonical_node_id
from mcts.scoring.attack_graph_policy import apply_policy_edges, seed_server_surfaces
from mcts.scoring.attack_graph_producers import export_all_edges
from mcts.scoring.graph_matcher import match_all_templates
from mcts.scoring.graph_templates import load_chain_templates


class GraphBuilder:
    """Phase 3a MVP graph construction pipeline."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig(target=".")

    def build(self, server: MCPServerInfo, findings: list[Finding]) -> AttackGraph:
        graph = AttackGraph()
        graph.seed_sources_and_sinks()
        seed_server_surfaces(graph, server)
        for edge in export_all_edges(server, findings):
            graph.merge_edge(edge)
        if self.config.attack_graph_include_overlap_chains:
            self._add_corroborated_invokes_edges(graph, server)
        apply_policy_edges(graph, server, findings)
        templates = load_chain_templates()
        max_depth = self.config.attack_graph_max_depth
        if max_depth > 0:
            templates = [
                template.model_copy(update={"max_depth": min(template.max_depth, max_depth)})
                for template in templates
            ]
        min_conf = self.config.attack_graph_min_confidence
        if min_conf > 0:
            templates = [
                template.model_copy(update={"min_confidence": max(template.min_confidence, min_conf)})
                for template in templates
            ]
        matched = match_all_templates(
            graph,
            templates,
            top_per_template=3,
        )
        graph.matched_chains = matched
        graph.total_risk_score = sum(chain.chain_risk_score for chain in matched)
        return graph

    def _add_corroborated_invokes_edges(self, graph: AttackGraph, server: MCPServerInfo) -> None:
        """Optional overlap chains — disabled by default (spec forever default False)."""
        tools = server.tools
        for src in tools:
            for dst in tools:
                if src.name == dst.name:
                    continue
                if src.source_file and src.source_file == dst.source_file:
                    graph.add_edge(
                        EdgeKind.INVOKES,
                        canonical_node_id("tool", src.name),
                        canonical_node_id("tool", dst.name),
                        confidence=0.45,
                        reachability=0.5,
                        evidence_strength="heuristic",
                        analysis_depth="L0",
                        label="corroborated_same_file",
                    )
