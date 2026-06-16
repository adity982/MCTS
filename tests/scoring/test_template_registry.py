"""Template registry CI validation."""

from __future__ import annotations

from mcts.scoring.graph_templates import TEMPLATES_DIR, load_templates


def test_template_registry_loads_all_yaml() -> None:
    templates = load_templates(TEMPLATES_DIR)
    assert len(templates) >= 4
    for template in templates:
        assert template.id
        assert template.anchor.first_edge
        assert template.edge_pattern
