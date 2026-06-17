"""Suggest attack-graph remediations from a scan report (Phase 3c)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcts.scoring.graph_fixes import describe_fixes
from mcts.scoring.graph_templates import load_chain_templates


def suggest_fixes_from_report(report_path: Path) -> list[dict[str, Any]]:
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    attack_graph = payload.get("attack_graph") or {}
    templates = {template.id: template for template in load_chain_templates()}
    suggestions: list[dict[str, Any]] = []
    seen: set[str] = set()

    for template_id in attack_graph.get("templates_matched") or []:
        if template_id in seen:
            continue
        seen.add(template_id)
        template = templates.get(str(template_id))
        if not template:
            continue
        suggestions.append(
            {
                "template_id": template_id,
                "title": template.title,
                "recommended_fixes": describe_fixes(list(template.recommended_fixes)),
            }
        )
    return suggestions
