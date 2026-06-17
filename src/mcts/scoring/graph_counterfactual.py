"""Counterfactual remediation for matched attack graph chains (Phase 3c)."""

from __future__ import annotations

from typing import Any

from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.graph_fixes import describe_fixes
from mcts.scoring.graph_mutate import simulate_fixes_for_template
from mcts.scoring.graph_templates import load_chain_templates


def counterfactual_for_chain(
    template_id: str,
    tools_on_path: list[str],
    *,
    graph: AttackGraph | None = None,
    fix_kinds: list[str] | None = None,
) -> dict[str, Any]:
    """Build counterfactual payload aligned with trust-layer evidence shape."""
    templates = {template.id: template for template in load_chain_templates()}
    template = templates.get(template_id)
    kinds = fix_kinds if fix_kinds is not None else (list(template.recommended_fixes) if template else [])
    fixes = describe_fixes(kinds)

    triggered: list[str] = []
    actions: list[dict[str, str]] = []
    tool_label = ", ".join(tools_on_path) if tools_on_path else "matched path"
    for fix in fixes:
        kind = str(fix.get("kind", ""))
        description = str(fix.get("description") or kind.replace("_", " "))
        triggered.append(f"{template_id}: {description} ({tool_label})")
        actions.append(
            {
                "action": description,
                "removes": kind or template_id,
            }
        )

    simulation: list[dict[str, Any]] = []
    if graph is not None and kinds:
        simulation = simulate_fixes_for_template(graph, template_id, kinds)

    eliminating = [row for row in simulation if row.get("eliminates_template")]
    payload: dict[str, Any] = {
        "triggered_by": triggered,
        "removing_any_one_eliminates_finding": len(eliminating) > 0 or len(fixes) > 1,
        "actions": actions,
        "recommended_fixes": fixes,
        "template_id": template_id,
    }
    if simulation:
        payload["fix_simulation"] = simulation
        payload["effective_fixes"] = [row["fix_kind"] for row in eliminating]
    return payload
