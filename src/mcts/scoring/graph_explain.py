"""Explanation generation for matched attack chains."""

from __future__ import annotations

from typing import Any

from mcts.reporting.finding_builder import FindingBuilder
from mcts.reporting.models import Finding, Severity
from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import ExplanationStep, GraphPath, MatchedChain, parse_node_id
from mcts.scoring.graph_risk import downgrade_severity
from mcts.scoring.graph_templates import ChainTemplate, load_chain_templates


def describe_edge(edge: Any, graph: AttackGraph) -> ExplanationStep:
    refs: list[str] = []
    for item in edge.evidence:
        if item.rule_id:
            refs.append(item.rule_id)
        if item.file and item.line:
            refs.append(f"{item.file}:{item.line}")
    if edge.policy:
        refs.append(f"policy:{edge.kind.value}")
    _, to_local = parse_node_id(edge.to_node)
    return ExplanationStep(
        message=f"{edge.kind.value} from {edge.from_node} to {edge.to_node} ({edge.label or to_local})",
        derived_from=refs or [edge.kind.value],
    )


def generate_explanation(
    path: GraphPath,
    template: ChainTemplate,
    graph: AttackGraph,
) -> list[ExplanationStep]:
    if template.explanation_steps:
        return [
            ExplanationStep(message=msg, derived_from=[f"template:{template.id}"])
            for msg in template.explanation_steps
        ]
    steps = [describe_edge(edge, graph) for edge in path.edges]
    steps.append(
        ExplanationStep(
            message=f"Matched template {template.id} with {path.hop_count} hops.",
            derived_from=[template.id],
        )
    )
    return steps


def matched_chain_to_finding(template_id: str, chains: list[MatchedChain]) -> Finding | None:
    if not chains:
        return None
    templates = {t.id: t for t in load_chain_templates()}
    template = templates.get(template_id)
    if template is None:
        return None
    top = chains[0]
    finding_id = top.legacy_finding_id or f"chain-{template_id.lower().replace('_', '-')}"
    severity = downgrade_severity(
        template.severity,
        path_conf=top.path_confidence,
        min_confidence=template.min_confidence,
        reach=top.path_reachability,
        min_reachability=template.min_reachability,
    )
    if top.path_confidence < 0.6:
        severity = downgrade_severity(
            severity,
            path_conf=top.path_confidence,
            min_confidence=0.6,
            reach=top.path_reachability,
            min_reachability=template.min_reachability,
        )
    paths_payload: list[dict[str, Any]] = []
    for chain in chains:
        paths_payload.append(
            {
                "nodes": chain.path.nodes,
                "edges": [edge.id for edge in chain.path.edges],
                "hop_count": chain.path.hop_count,
                "tools_on_path": chain.path.tool_names_on_path(),
                "chain_confidence": round(chain.path_confidence, 3),
                "path_reachability": round(chain.path_reachability, 3),
                "chain_risk_score": round(chain.chain_risk_score, 3),
                "explanation": [step.model_dump(mode="json") for step in chain.explanation],
            }
        )
    builder = (
        FindingBuilder(
            finding_id=finding_id,
            analyzer="attack_graph",
            title=template.title,
            description=f"Attack graph matched template {template_id}.",
            severity=Severity(severity),
            recommendation="; ".join(template.recommended_fixes) or "Review matched attack path.",
        )
        .confidence(top.path_confidence)
        .technique("MCTS-T-attack-graph")
        .evidence(
            template_id=template_id,
            path_proven=top.path.hop_count >= 2,
            chain_confidence=round(top.path_confidence, 3),
            path_reachability=round(top.path_reachability, 3),
            chain_risk_score=round(top.chain_risk_score, 3),
            trust_boundary_crossings=top.trust_boundary_crossings,
            exploit_cost=template.exploit_cost,
            paths=paths_payload,
            finding_class=template.finding_class,
        )
        .fact(
            rule_id=template_id,
            match=template.title,
            field="attack_graph",
        )
    )
    tools = top.path.tool_names_on_path()
    if tools:
        builder = builder.tool(tools[0])
    return builder.build(require_fact=False)
