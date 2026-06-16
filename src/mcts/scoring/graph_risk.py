"""Risk scoring helpers for attack graph paths (Phase 3a)."""

from __future__ import annotations

from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import GraphPath, TrustLevel
from mcts.scoring.graph_templates import ChainTemplate

SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
}


def geometric_mean(values: list[float]) -> float:
    if not values:
        return 0.0
    product = 1.0
    for value in values:
        product *= value
    return product ** (1.0 / len(values))


def path_confidence(path: GraphPath) -> float:
    return geometric_mean([edge.confidence for edge in path.edges])


def path_reachability(path: GraphPath) -> float:
    return geometric_mean([edge.reachability for edge in path.edges])


def _is_risk_increasing_crossing(from_trust: str, to_sensitivity: str) -> bool:
    return from_trust == TrustLevel.UNTRUSTED.value and to_sensitivity in {
        "critical",
        "high",
        "medium",
    }


def trust_crossing_count(path: GraphPath, graph: AttackGraph) -> int:
    count = 0
    for idx in range(len(path.nodes) - 1):
        from_node = path.nodes[idx]
        to_node = path.nodes[idx + 1]
        from_trust = graph.trust(from_node)
        to_sensitivity = graph.sensitivity(to_node)
        if _is_risk_increasing_crossing(from_trust, to_sensitivity):
            count += 1
    return count


def trust_multiplier(crossings: int) -> float:
    return min(1.35, 1.0 + 0.10 * crossings)


def chain_risk_score(template: ChainTemplate, path: GraphPath, graph: AttackGraph) -> float:
    conf = path_confidence(path)
    reach = path_reachability(path)
    sev = SEVERITY_WEIGHT.get(template.severity.lower(), 7.0)
    trust_m = trust_multiplier(trust_crossing_count(path, graph))
    cost = max(template.exploit_cost, 1)
    return (sev * conf * reach * trust_m) / cost


def downgrade_severity(
    severity: str,
    *,
    path_conf: float,
    min_confidence: float,
    reach: float,
    min_reachability: float,
) -> str:
    from mcts.reporting.models import Severity

    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    try:
        current = Severity(severity.lower())
    except ValueError:
        current = Severity.HIGH
    idx = order.index(current)
    if path_conf < min_confidence and idx > 0:
        idx -= 1
    if reach < min_reachability and idx > 0:
        idx -= 1
    return order[idx].value
