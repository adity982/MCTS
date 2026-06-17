"""Path compression for attack graph dashboard export (Phase 3c)."""

from __future__ import annotations

from typing import Any


def _path_key(path: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    template_id = str(path.get("template_id") or "")
    tools = tuple(sorted(path.get("tools_on_path") or path.get("nodes") or []))
    return template_id, tools


def compress_paths(
    paths: list[dict[str, Any]],
    *,
    max_total: int = 12,
    max_per_template: int = 2,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Dedupe by template + tool set; keep highest chain_risk_score paths."""
    if not paths or len(paths) <= max_total:
        return paths, {"original_count": len(paths), "compressed_count": len(paths), "dropped": 0}

    by_template: dict[str, list[dict[str, Any]]] = {}
    for path in paths:
        template_id = str(path.get("template_id") or "unknown")
        by_template.setdefault(template_id, []).append(path)

    ranked: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, tuple[str, ...]]] = set()
    for _template_id, group in sorted(by_template.items()):
        group_sorted = sorted(
            group,
            key=lambda row: float(row.get("chain_risk_score") or 0),
            reverse=True,
        )
        kept = 0
        for path in group_sorted:
            key = _path_key(path)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            ranked.append(path)
            kept += 1
            if kept >= max_per_template:
                break

    ranked.sort(key=lambda row: float(row.get("chain_risk_score") or 0), reverse=True)
    compressed = ranked[:max_total]
    return compressed, {
        "original_count": len(paths),
        "compressed_count": len(compressed),
        "dropped": max(0, len(paths) - len(compressed)),
    }
