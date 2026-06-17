"""Inventory-layer edges for multi-server attack graphs (Phase 3c)."""

from __future__ import annotations

import re

from mcts.inventory.models import InventoryEntry
from mcts.scoring.attack_graph import AttackGraph
from mcts.scoring.attack_graph_models import EdgeKind, GraphLayer, NodeKind, canonical_node_id

_READ_TOOLS = frozenset({"read_file", "get_env", "read_env", "fetch", "http_request"})
_WRITE_TOOLS = frozenset({"write_file", "delete_file", "run_shell", "execute_command", "deploy"})
_SENSITIVE_TOOLS = frozenset(
    {
        "read_file",
        "write_file",
        "delete_file",
        "run_shell",
        "execute_command",
        "http_request",
        "fetch",
        "post_webhook",
        "get_env",
        "read_env",
    }
)


def _server_slug(server_key: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", server_key).strip("_")


def server_hub_id(server_key: str) -> str:
    return canonical_node_id(NodeKind.CAPABILITY, f"inventory-{_server_slug(server_key)}")


def inventory_tool_id(server_key: str, tool_name: str) -> str:
    return canonical_node_id(NodeKind.TOOL, f"{_server_slug(server_key)}::{tool_name}")


def attach_inventory_layer(graph: AttackGraph, inventory: list[InventoryEntry]) -> None:
    """Merge cross-server inventory nodes and edges when fleet size >= 2."""
    if len(inventory) < 2:
        return

    server_tools: dict[str, set[str]] = {}
    server_meta: dict[str, InventoryEntry] = {}

    for entry in inventory:
        server_key = f"{entry.client}/{entry.server_name}"
        server_meta[server_key] = entry
        tools = {tool.lower() for tool in entry.tools}
        server_tools[server_key] = tools

        hub = server_hub_id(server_key)
        graph.add_node(
            NodeKind.CAPABILITY,
            hub.split(":", 1)[1],
            label=server_key,
            layer=GraphLayer.INVENTORY,
            metadata={"server_key": server_key, "client": entry.client, "server_name": entry.server_name},
        )
        for tool in sorted(entry.tools):
            local = f"{_server_slug(server_key)}::{tool}"
            graph.add_node(
                NodeKind.TOOL,
                local,
                label=f"{tool} ({server_key})",
                layer=GraphLayer.INVENTORY,
                metadata={"server_key": server_key, "tool": tool},
            )
            graph.add_edge(
                EdgeKind.EXPOSES,
                hub,
                inventory_tool_id(server_key, tool),
                layer=GraphLayer.INVENTORY,
                confidence=0.9,
                reachability=1.0,
                label="inventory_tool_surface",
                policy=True,
            )
            unscoped = canonical_node_id(NodeKind.TOOL, tool)
            if unscoped in graph.nodes:
                graph.add_edge(
                    EdgeKind.INVOKES,
                    unscoped,
                    inventory_tool_id(server_key, tool),
                    layer=GraphLayer.INVENTORY,
                    confidence=0.95,
                    reachability=1.0,
                    label="focal_server_bridge",
                    policy=True,
                )

    readers = [key for key, tools in server_tools.items() if tools & _READ_TOOLS]
    writers = [key for key, tools in server_tools.items() if tools & _WRITE_TOOLS]
    for reader in readers:
        read_tools = sorted(server_tools[reader] & _READ_TOOLS)
        for writer in writers:
            if reader == writer:
                continue
            write_tools = sorted(server_tools[writer] & _WRITE_TOOLS)
            if not read_tools or not write_tools:
                continue
            from_tool = inventory_tool_id(reader, read_tools[0])
            to_tool = inventory_tool_id(writer, write_tools[0])
            graph.add_edge(
                EdgeKind.INVOKES,
                from_tool,
                to_tool,
                layer=GraphLayer.INVENTORY,
                confidence=0.75,
                reachability=0.8,
                label="cross_server_read_write",
                policy=True,
                metadata={"reader": reader, "writer": writer, "issue": "W015"},
            )
            graph.add_edge(
                EdgeKind.INVOKES,
                server_hub_id(reader),
                server_hub_id(writer),
                layer=GraphLayer.INVENTORY,
                confidence=0.7,
                reachability=0.75,
                label="cross_server_toxic_flow",
                policy=True,
                metadata={"reader": reader, "writer": writer, "issue": "W015"},
            )

    for tool in _SENSITIVE_TOOLS:
        holders = sorted(key for key, tools in server_tools.items() if tool in tools)
        if len(holders) < 2:
            continue
        for left in holders:
            for right in holders:
                if left >= right:
                    continue
                graph.add_edge(
                    EdgeKind.INVOKES,
                    inventory_tool_id(left, tool),
                    inventory_tool_id(right, tool),
                    layer=GraphLayer.INVENTORY,
                    confidence=0.65,
                    reachability=0.7,
                    label="sensitive_tool_shadow",
                    policy=True,
                    metadata={"tool": tool, "servers": holders, "issue": "W016"},
                )
