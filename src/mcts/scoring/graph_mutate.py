"""Apply FixKind registry mutates to attack graphs (Phase 3c runtime engine)."""

from __future__ import annotations

import fnmatch
from typing import Any

from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, GraphLayer, parse_node_id
from mcts.scoring.graph_fixes import resolve_fix
from mcts.scoring.graph_matcher import match_template
from mcts.scoring.graph_templates import ChainTemplate, load_chain_templates


def clone_graph(graph: AttackGraph) -> AttackGraph:
    """Deep-copy nodes and edges without matched chains."""
    copy = AttackGraph()
    copy._nodes = {node_id: node.model_copy(deep=True) for node_id, node in graph.nodes.items()}
    for edge in graph.edges.values():
        copy.merge_edge(edge.model_copy(deep=True))
    return copy


def _remove_node(graph: AttackGraph, node_id: str) -> None:
    if node_id not in graph.nodes:
        return
    edge_ids = [
        edge.id for edge in graph.edges.values() if edge.from_node == node_id or edge.to_node == node_id
    ]
    for edge_id in edge_ids:
        edge = graph.edges.get(edge_id)
        if not edge:
            continue
        graph._edges.pop(edge_id, None)
        if edge.kind in graph._edges_by_kind:
            graph._edges_by_kind[edge.kind] = [
                eid for eid in graph._edges_by_kind[edge.kind] if eid != edge_id
            ]
        if edge.from_node in graph._outgoing:
            graph._outgoing[edge.from_node] = [
                eid for eid in graph._outgoing[edge.from_node] if eid != edge_id
            ]
        graph._nodes_with_outgoing_kind.setdefault(edge.kind, set()).discard(edge.from_node)
    graph._nodes.pop(node_id, None)


def _node_matches_pattern(node_id: str, pattern: str) -> bool:
    if fnmatch.fnmatch(node_id, pattern):
        return True
    _, local = parse_node_id(node_id)
    return fnmatch.fnmatch(local, pattern)


def apply_mutate_spec(graph: AttackGraph, spec: dict[str, Any]) -> None:
    """Apply one registry mutate block to *graph* in place."""
    if "add_edge" in spec:
        payload = spec["add_edge"]
        kind = EdgeKind(str(payload["kind"]))
        graph.add_edge(
            kind,
            str(payload["from"]),
            str(payload["to"]),
            layer=GraphLayer(payload["layer"]) if payload.get("layer") else None,
            confidence=float(payload.get("confidence", 0.85)),
            reachability=float(payload.get("reachability", 1.0)),
            label=str(payload.get("label", "fix_mutate")),
            policy=bool(payload.get("policy", True)),
        )
        return

    if "set_reachability" in spec:
        payload = spec["set_reachability"]
        edge_kind = EdgeKind(str(payload["edge_kind"]))
        value = float(payload["value"])
        for edge in graph.edges_of_kind(edge_kind):
            edge.reachability = value
        return

    if "remove_nodes" in spec:
        payload = spec["remove_nodes"]
        kind_value = str(payload["kind"])
        targets = [
            node_id
            for node_id, node in graph.nodes.items()
            if node.kind.value == kind_value or parse_node_id(node_id)[0] == kind_value
        ]
        for node_id in targets:
            _remove_node(graph, node_id)
        return

    if "remove_node" in spec:
        pattern = str(spec["remove_node"]["pattern"])
        targets = [node_id for node_id in graph.nodes if _node_matches_pattern(node_id, pattern)]
        for node_id in targets:
            _remove_node(graph, node_id)


def apply_fix_kind(graph: AttackGraph, fix_kind: str) -> AttackGraph:
    """Return a mutated graph copy after applying all mutates for *fix_kind*."""
    entry = resolve_fix(fix_kind)
    mutated = clone_graph(graph)
    if not entry:
        return mutated
    for spec in entry.get("mutates") or []:
        if isinstance(spec, dict):
            apply_mutate_spec(mutated, spec)
    return mutated


def simulate_fix_eliminates_template(
    graph: AttackGraph,
    template: ChainTemplate,
    fix_kind: str,
) -> bool:
    """True when applying *fix_kind* removes all matches for *template*."""
    mutated = apply_fix_kind(graph, fix_kind)
    return len(match_template(template, mutated)) == 0


def simulate_fixes_for_template(
    graph: AttackGraph,
    template_id: str,
    fix_kinds: list[str],
) -> list[dict[str, Any]]:
    """Evaluate each fix kind against the live graph for counterfactual simulation."""
    templates = {template.id: template for template in load_chain_templates()}
    template = templates.get(template_id)
    if template is None:
        return []
    results: list[dict[str, Any]] = []
    for kind in fix_kinds:
        entry = resolve_fix(kind) or {"kind": kind}
        eliminates = simulate_fix_eliminates_template(graph, template, kind)
        results.append(
            {
                "fix_kind": kind,
                "description": str(entry.get("description") or kind.replace("_", " ")),
                "eliminates_template": eliminates,
                "mutates_applied": len(entry.get("mutates") or []),
            }
        )
    return results


def any_fix_eliminates_template(
    graph: AttackGraph,
    template_id: str,
    fix_kinds: list[str],
) -> bool:
    rows = simulate_fixes_for_template(graph, template_id, fix_kinds)
    return any(row["eliminates_template"] for row in rows)


def minimal_fix_set(
    graph: AttackGraph,
    template_id: str,
    fix_kinds: list[str],
) -> list[str]:
    """Greedy single-fix hits that eliminate the template (for doctor suggestions)."""
    return [
        row["fix_kind"]
        for row in simulate_fixes_for_template(graph, template_id, fix_kinds)
        if row["eliminates_template"]
    ]
