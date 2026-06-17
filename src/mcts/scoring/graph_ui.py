"""Attack graph normalization for dashboard HTML and SARIF export."""

from __future__ import annotations

from typing import Any


def normalize_attack_graph_for_ui(graph: dict[str, Any]) -> dict[str, Any]:
    """Convert v3 graph dict to dashboard-friendly nodes/edges/paths."""
    if not graph:
        return {"nodes": [], "edges": [], "paths": [], "version": 2}
    version = graph.get("version", 2)
    if version < 3:
        return graph

    nodes = []
    for node in graph.get("nodes") or []:
        if isinstance(node, dict):
            nodes.append(
                {
                    "id": node.get("id", ""),
                    "label": node.get("label") or _short_label(node.get("id", "")),
                    "type": node.get("kind", "tool"),
                    "kind": node.get("kind"),
                    "layer": node.get("layer"),
                    "trust": node.get("trust"),
                    "sensitivity": node.get("sensitivity"),
                }
            )

    edges = []
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        src = edge.get("from_node") or edge.get("from")
        dst = edge.get("to_node") or edge.get("to")
        policy = bool(edge.get("policy", False))
        evidence_strength = edge.get("evidence_strength") or "static"
        edges.append(
            {
                "from": src,
                "to": dst,
                "label": edge.get("label") or edge.get("kind", ""),
                "kind": edge.get("kind"),
                "layer": edge.get("layer"),
                "policy": policy,
                "evidence_strength": evidence_strength,
                "edge_class": "policy" if policy else _edge_class(evidence_strength),
            }
        )

    paths = []
    for path in graph.get("paths") or []:
        if not isinstance(path, dict):
            continue
        paths.append(
            {
                "id": path.get("id"),
                "template_id": path.get("template_id"),
                "nodes": path.get("nodes") or path.get("tools_on_path") or [],
                "hop_count": path.get("hop_count", 0),
                "chain_confidence": path.get("chain_confidence"),
                "path_reachability": path.get("path_reachability"),
                "chain_risk_score": path.get("chain_risk_score"),
                "explanation": path.get("explanation") or [],
                "finding_ids": path.get("finding_ids") or [],
                "recommended_fixes": path.get("recommended_fixes") or [],
                "counterfactual_remediation": path.get("counterfactual_remediation"),
            }
        )

    layers_present = graph.get("layers_present") or sorted(
        {layer for node in nodes if (layer := node.get("layer"))}
        | {layer for edge in edges if (layer := edge.get("layer"))}
    )

    return {
        "version": version,
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
        "templates_matched": graph.get("templates_matched") or [],
        "total_risk_score": graph.get("total_risk_score"),
        "layers_present": layers_present,
        "compression_stats": graph.get("compression_stats"),
    }


def format_attack_path_explanation(finding: Any) -> str:
    """Build SARIF/HTML-friendly explanation text for attack_graph findings."""
    evidence = finding.evidence or {}
    paths = evidence.get("paths") or []
    if not paths:
        return finding.description or ""
    lines: list[str] = []
    top = paths[0] if isinstance(paths[0], dict) else {}
    template_id = evidence.get("template_id") or top.get("template_id")
    if template_id:
        lines.append(f"Template: {template_id}")
    conf = evidence.get("chain_confidence") or top.get("chain_confidence")
    reach = evidence.get("path_reachability") or top.get("path_reachability")
    risk = evidence.get("chain_risk_score") or top.get("chain_risk_score")
    if conf is not None or reach is not None or risk is not None:
        lines.append(f"Confidence: {conf} | Reachability: {reach} | Risk score: {risk}")
    explanation = top.get("explanation") or []
    if explanation:
        lines.append("Explanation:")
        for idx, step in enumerate(explanation, start=1):
            if isinstance(step, dict):
                lines.append(f"{idx}. {step.get('message', step)}")
            else:
                lines.append(f"{idx}. {step}")
    counterfactual = evidence.get("counterfactual_remediation")
    if isinstance(counterfactual, dict) and counterfactual.get("actions"):
        lines.append("Counterfactual fixes:")
        for action in counterfactual.get("actions") or []:
            if isinstance(action, dict):
                lines.append(f"- {action.get('action', action)}")
    return "\n".join(lines) if lines else (finding.description or "")


def _edge_class(evidence_strength: str) -> str:
    if evidence_strength == "runtime":
        return "runtime"
    if evidence_strength == "heuristic":
        return "inferred"
    return "proven"


def _short_label(node_id: str) -> str:
    if ":" in node_id:
        return node_id.split(":", 1)[1]
    return node_id
