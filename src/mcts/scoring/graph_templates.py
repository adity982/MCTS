"""YAML chain template loading and schema (Phase 3a MVP)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from mcts.scoring.attack_graph_models import EdgeKind, GraphLayer

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
FIXES_REGISTRY_PATH = Path(__file__).resolve().parent / "fixes" / "registry.yaml"

_LEGACY_DELIVERS = "DELIVERS_TO"


class EdgePattern(BaseModel):
    kind: str | None = None
    kinds: list[str] = Field(default_factory=list)
    from_kind: str | None = None
    to_kind: str | None = None
    to: str | None = None
    from_node: str | None = Field(default=None, alias="from")

    model_config = {"populate_by_name": True}

    def matching_kinds(self) -> list[str]:
        if self.kinds:
            return list(self.kinds)
        if self.kind:
            return [self.kind]
        return []


class TemplateAnchor(BaseModel):
    first_edge: str


class ChainTemplate(BaseModel):
    id: str
    title: str
    severity: str = "high"
    finding_class: str = "security"
    min_confidence: float = 0.6
    min_reachability: float = 0.25
    max_depth: int = 6
    exploit_cost: int = 2
    anchor: TemplateAnchor
    layers: list[str] = Field(default_factory=list)
    edge_pattern: list[EdgePattern] = Field(default_factory=list)
    node_filters: dict[str, Any] = Field(default_factory=dict)
    recommended_fixes: list[str] = Field(default_factory=list)
    explanation_steps: list[str] = Field(default_factory=list)
    legacy_finding_id: str | None = None

    def layer_enums(self) -> list[GraphLayer]:
        if not self.layers:
            return []
        return [GraphLayer(layer) for layer in self.layers]


def migrate_legacy_delivers_to(data: dict[str, Any]) -> dict[str, Any]:
    """Map deprecated ``DELIVERS_TO`` edge kinds to ``DELIVERS_TO_CONTEXT``."""
    patterns = data.get("edge_pattern") or []
    for pattern in patterns:
        if not isinstance(pattern, dict):
            continue
        for key in ("kind", "kinds"):
            value = pattern.get(key)
            if value == _LEGACY_DELIVERS:
                pattern[key] = EdgeKind.DELIVERS_TO_CONTEXT.value
            elif isinstance(value, list):
                pattern[key] = [
                    EdgeKind.DELIVERS_TO_CONTEXT.value if v == _LEGACY_DELIVERS else v for v in value
                ]
    anchor = data.get("anchor") or {}
    if anchor.get("first_edge") == _LEGACY_DELIVERS:
        anchor["first_edge"] = EdgeKind.DELIVERS_TO_CONTEXT.value
    return data


def load_template(path: Path) -> ChainTemplate:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Invalid template YAML: {path}")
    return ChainTemplate.model_validate(migrate_legacy_delivers_to(raw))


def load_templates(directory: Path | None = None) -> list[ChainTemplate]:
    root = directory or TEMPLATES_DIR
    templates: list[ChainTemplate] = []
    for path in sorted(root.glob("*.yaml")):
        templates.append(load_template(path))
    return templates


def load_mvp_templates() -> list[ChainTemplate]:
    """Load only Phase 3a MVP template IDs."""
    allowed = {"SSRF_EXFIL", "READ_EXFIL", "HTTP_TAKEOVER", "MEMORY_POISON"}
    return [t for t in load_templates() if t.id in allowed]


def load_chain_templates() -> list[ChainTemplate]:
    """Load all registered chain templates (Phase 3a + 3b)."""
    return load_templates()


def load_fixes_registry(path: Path | None = None) -> dict[str, Any]:
    registry_path = path or FIXES_REGISTRY_PATH
    if not registry_path.is_file():
        return {}
    raw = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}
