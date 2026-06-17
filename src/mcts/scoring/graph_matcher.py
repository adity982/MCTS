"""Template matching and bounded path enumeration for attack graph v3."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from mcts.scoring.attack_graph import AttackGraph, build_path_from_edges
from mcts.scoring.attack_graph_models import (
    EdgeKind,
    GraphEdge,
    GraphPath,
    MatchedChain,
    NodeKind,
    is_path_terminal,
    parse_node_id,
)
from mcts.scoring.graph_risk import chain_risk_score, path_confidence, path_reachability, trust_crossing_count
from mcts.scoring.graph_templates import ChainTemplate, EdgePattern

_INTERMEDIATE_SINKS = frozenset({"sink:env", "sink:disk", "sink:cross_session", "sink:external_network"})


def _edge_stays_on_tool(edge: GraphEdge) -> bool:
    if edge.to_node in _INTERMEDIATE_SINKS:
        return True
    if edge.to_node.startswith("source:"):
        return True
    return edge.to_node.startswith("resource:") and edge.kind == EdgeKind.READS


_EDGE_KIND_ORDER = {
    EdgeKind.READS: 0,
    EdgeKind.WRITES: 1,
    EdgeKind.PERSISTS: 2,
    EdgeKind.INVOKES: 2,
    EdgeKind.EGRESS: 3,
    EdgeKind.EXPOSES: 4,
    EdgeKind.DELIVERS_TO_CONTEXT: 5,
    EdgeKind.RESOURCE_READABLE_BY_CONTEXT: 6,
}


def _sorted_out_edges(graph: AttackGraph, node_id: str) -> list[GraphEdge]:
    return sorted(
        graph.out_edges(node_id),
        key=lambda edge: (_EDGE_KIND_ORDER.get(edge.kind, 99), edge.to_node),
    )


def enumerate_paths(
    graph: AttackGraph,
    start: str,
    *,
    max_depth: int = 6,
) -> Iterator[GraphPath]:
    """Bounded DFS with per-path visited set; sinks are terminal."""
    stack: list[tuple[str, list[GraphEdge], set[str], set[str]]] = [(start, [], {start}, set())]
    while stack:
        node, edges, visited, used_edge_ids = stack.pop()
        if len(edges) >= max_depth:
            continue
        out_edges = _sorted_out_edges(graph, node)
        if edges and (is_path_terminal(node) or not out_edges):
            yield build_path_from_edges(start, edges)
            continue
        intermediate = [e for e in out_edges if _edge_stays_on_tool(e)]
        non_terminal = [
            e for e in out_edges if not _edge_stays_on_tool(e) and not is_path_terminal(e.to_node)
        ]
        terminal = [e for e in out_edges if is_path_terminal(e.to_node)]
        for edge in terminal + non_terminal + intermediate:
            if edge.id in used_edge_ids:
                continue
            nxt = edge.to_node
            next_edges = [*edges, edge]
            next_used = used_edge_ids | {edge.id}
            if _edge_stays_on_tool(edge):
                stack.append((node, next_edges, visited, next_used))
                continue
            if nxt in visited:
                continue
            stack.append((nxt, next_edges, visited | {nxt}, next_used))


def _edge_matches_pattern(edge: GraphEdge, pattern: EdgePattern) -> bool:
    kinds = pattern.matching_kinds()
    if kinds and edge.kind.value not in kinds:
        return False
    if pattern.to and edge.to_node != pattern.to:
        return False
    if pattern.from_node and edge.from_node != pattern.from_node:
        return False
    if pattern.from_kind:
        from_kind, _ = parse_node_id(edge.from_node)
        if from_kind != pattern.from_kind:
            return False
    if pattern.to_kind:
        to_kind, _ = parse_node_id(edge.to_node)
        if to_kind != pattern.to_kind:
            return False
    return True


def path_satisfies_pattern(path: GraphPath, patterns: list[EdgePattern]) -> bool:
    """Match consecutive edge kinds along the path (not necessarily contiguous nodes)."""
    if not patterns:
        return False
    edge_idx = 0
    pattern_idx = 0
    while edge_idx < len(path.edges) and pattern_idx < len(patterns):
        if _edge_matches_pattern(path.edges[edge_idx], patterns[pattern_idx]):
            pattern_idx += 1
        edge_idx += 1
    return pattern_idx == len(patterns)


def _path_passes_node_filters(path: GraphPath, filters: dict[str, Any]) -> bool:
    if not filters:
        return True
    tool_names = path.tool_names_on_path()
    contains = filters.get("tool_name_contains") or []
    if contains:
        lowered = [name.lower() for name in tool_names]
        if not any(any(token.lower() in name for token in contains) for name in lowered):
            return False
    prefixes = filters.get("tool_name_prefix") or []
    if not prefixes:
        return True
    return any(name.lower().startswith(tuple(prefixes)) for name in tool_names)


def _http_takeover_has_tool_between_exposes_and_env(path: GraphPath) -> bool:
    """HTTP_TAKEOVER requires a tool node between EXPOSES and READS(env)."""
    exposes_idx = next((i for i, e in enumerate(path.edges) if e.kind.value == "EXPOSES"), None)
    env_read_idx = next(
        (i for i, e in enumerate(path.edges) if e.kind.value == "READS" and e.to_node == "sink:env"),
        None,
    )
    if exposes_idx is None or env_read_idx is None or env_read_idx <= exposes_idx:
        return False
    for node_id in path.nodes[exposes_idx : env_read_idx + 1]:
        kind, _ = parse_node_id(node_id)
        if kind == NodeKind.TOOL.value:
            return True
    return False


def match_template(template: ChainTemplate, graph: AttackGraph) -> list[MatchedChain]:
    subgraph = graph.filter_layers(template.layer_enums()) if template.layer_enums() else graph
    try:
        from mcts.scoring.attack_graph_models import EdgeKind

        anchor_kind = EdgeKind(template.anchor.first_edge)
    except ValueError:
        return []
    start_nodes = subgraph.nodes_with_outgoing(anchor_kind)
    matches: list[MatchedChain] = []
    for start in start_nodes:
        for path in enumerate_paths(subgraph, start, max_depth=template.max_depth):
            if not path_satisfies_pattern(path, template.edge_pattern):
                continue
            if template.id == "HTTP_TAKEOVER" and not _http_takeover_has_tool_between_exposes_and_env(path):
                continue
            if not _path_passes_node_filters(path, template.node_filters):
                continue
            conf = path_confidence(path)
            reach = path_reachability(path)
            if conf < template.min_confidence or reach < template.min_reachability:
                continue
            crossings = trust_crossing_count(path, graph)
            risk = chain_risk_score(template, path, graph)
            from mcts.scoring.graph_explain import generate_explanation

            matches.append(
                MatchedChain(
                    template_id=template.id,
                    path=path,
                    path_confidence=conf,
                    path_reachability=reach,
                    chain_risk_score=risk,
                    trust_boundary_crossings=crossings,
                    explanation=generate_explanation(path, template, graph),
                    legacy_finding_id=template.legacy_finding_id,
                )
            )
    return matches


def _tool_set_key(chain: MatchedChain) -> tuple[str, ...]:
    return tuple(sorted(chain.path.tool_names_on_path()))


def rank_and_dedupe(chains: list[MatchedChain], *, top_per_template: int = 3) -> list[MatchedChain]:
    by_template: dict[str, list[MatchedChain]] = {}
    for chain in chains:
        by_template.setdefault(chain.template_id, []).append(chain)
    ranked: list[MatchedChain] = []
    for _template_id, group in by_template.items():
        seen_tools: set[tuple[str, ...]] = set()
        sorted_group = sorted(group, key=lambda c: c.chain_risk_score, reverse=True)
        kept: list[MatchedChain] = []
        for chain in sorted_group:
            key = _tool_set_key(chain)
            if key in seen_tools:
                continue
            seen_tools.add(key)
            kept.append(chain)
            if len(kept) >= top_per_template:
                break
        ranked.extend(kept)
    return ranked


def match_all_templates(
    graph: AttackGraph,
    templates: list[ChainTemplate],
    *,
    top_per_template: int = 3,
) -> list[MatchedChain]:
    all_matches: list[MatchedChain] = []
    for template in templates:
        all_matches.extend(match_template(template, graph))
    return rank_and_dedupe(all_matches, top_per_template=top_per_template)
