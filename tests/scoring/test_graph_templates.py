"""YAML template loader tests."""

from __future__ import annotations

from mcts.scoring.graph_templates import (
    TEMPLATES_DIR,
    load_chain_templates,
    load_mvp_templates,
    load_template,
    migrate_legacy_delivers_to,
)


def test_load_all_mvp_templates() -> None:
    templates = load_mvp_templates()
    ids = {template.id for template in templates}
    assert ids == {"SSRF_EXFIL", "READ_EXFIL", "HTTP_TAKEOVER", "MEMORY_POISON"}


def test_load_chain_templates_includes_phase_3b() -> None:
    templates = load_chain_templates()
    ids = {template.id for template in templates}
    assert "SSRF_RESOURCE" in ids
    assert "ENV_SAMPLING" in ids
    assert "CRED_THEFT" in ids
    assert len(ids) >= 12


def test_migrate_legacy_delivers_to() -> None:
    raw = {
        "id": "LEGACY",
        "title": "legacy",
        "anchor": {"first_edge": "DELIVERS_TO"},
        "edge_pattern": [{"kind": "DELIVERS_TO"}],
    }
    migrated = migrate_legacy_delivers_to(raw)
    assert migrated["anchor"]["first_edge"] == "DELIVERS_TO_CONTEXT"
    assert migrated["edge_pattern"][0]["kind"] == "DELIVERS_TO_CONTEXT"


def test_template_has_anchor_and_pattern() -> None:
    template = load_template(TEMPLATES_DIR / "SSRF_EXFIL.yaml")
    assert template.anchor.first_edge == "EGRESS"
    assert len(template.edge_pattern) >= 2
