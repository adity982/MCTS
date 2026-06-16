"""MCP discovery modules."""

from mcts.discovery.monorepo import (
    MonorepoPackage,
    collect_surface_files,
    discover_monorepo,
    discover_monorepo_packages,
    expand_static_surface,
)
from mcts.discovery.static import StaticDiscovery
from mcts.discovery.static_js import JsStaticDiscovery
from mcts.discovery.static_runner import discover_static

__all__ = [
    "StaticDiscovery",
    "JsStaticDiscovery",
    "MonorepoPackage",
    "collect_surface_files",
    "discover_monorepo",
    "discover_monorepo_packages",
    "discover_static",
    "expand_static_surface",
]
