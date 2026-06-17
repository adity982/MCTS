"""FixKind registry for attack graph template remediations (Phase 3c)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

FIXES_REGISTRY_PATH = Path(__file__).resolve().parent / "fixes" / "registry.yaml"


@lru_cache(maxsize=1)
def load_fixes_registry() -> dict[str, dict[str, Any]]:
    if not FIXES_REGISTRY_PATH.exists():
        return {}
    raw = yaml.safe_load(FIXES_REGISTRY_PATH.read_text(encoding="utf-8")) or {}
    return {str(key): value for key, value in raw.items() if isinstance(value, dict)}


def resolve_fix(kind: str) -> dict[str, Any] | None:
    entry = load_fixes_registry().get(kind)
    if not entry:
        return None
    return {"kind": kind, **entry}


def describe_fixes(fix_kinds: list[str]) -> list[dict[str, Any]]:
    """Map template recommended_fixes keys to registry descriptions."""
    described: list[dict[str, Any]] = []
    for kind in fix_kinds:
        entry = resolve_fix(kind)
        if entry:
            described.append(entry)
        else:
            described.append(
                {
                    "kind": kind,
                    "description": kind.replace("_", " "),
                }
            )
    return described
