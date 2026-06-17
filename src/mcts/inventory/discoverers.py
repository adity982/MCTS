"""Discover MCP client configuration files."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.inventory.client_registry import config_paths_for_platform
from mcts.inventory.models import InventoryEntry


def redact_home(path_str: str) -> str:
    """Replace the user's home directory prefix with ``~`` when paths resolve under it."""
    if not path_str:
        return path_str
    try:
        home = Path.home().resolve()
        expanded = Path(path_str).expanduser()
        resolved = expanded.resolve()
    except (OSError, RuntimeError):
        return path_str

    home_text = str(home)
    resolved_text = str(resolved)
    if resolved_text == home_text:
        return "~"
    for sep in ("/", "\\"):
        prefix = home_text + sep
        if resolved_text.startswith(prefix):
            return "~" + resolved_text[len(home_text) :].replace("\\", "/")
    return path_str


def redact_entry_dict(data: dict, *, redact: bool) -> dict:
    if not redact:
        return data
    out = dict(data)
    if "config_path" in out:
        out["config_path"] = redact_home(str(out["config_path"]))
    return out


def redact_skill_dict(data: dict, *, redact: bool) -> dict:
    if not redact:
        return data
    out = dict(data)
    if "skill_path" in out:
        out["skill_path"] = redact_home(str(out["skill_path"]))
    return out


def discover_config_paths() -> list[tuple[str, Path]]:
    rows: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for client, raw in config_paths_for_platform():
        path = Path(raw).expanduser()
        if not path.exists():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        rows.append((client, path))
    return rows


def parse_config_file(client: str, path: Path) -> list[InventoryEntry]:
    try:
        from mcts.discovery.json5_util import load_json5

        if path.suffix.lower() in (".json5", ".jsonc"):
            payload = load_json5(path)
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []

    servers = _extract_mcp_servers(payload, client)
    entries: list[InventoryEntry] = []
    for server_name, config in servers.items():
        if not isinstance(config, dict):
            continue
        command = config.get("command")
        args = config.get("args") or []
        env_keys = sorted((config.get("env") or {}).keys())
        entries.append(
            InventoryEntry(
                client=client,
                config_path=str(path),
                server_name=server_name,
                command=command,
                args=[str(a) for a in args],
                env_keys=env_keys,
            )
        )
    return entries


def _extract_mcp_servers(payload: dict, client: str) -> dict:
    if "mcpServers" in payload and isinstance(payload["mcpServers"], dict):
        return payload["mcpServers"]
    if client == "vscode" and isinstance(payload.get("mcp"), dict):
        servers = payload["mcp"].get("servers")
        return servers if isinstance(servers, dict) else {}
    if isinstance(payload.get("modelContextProtocolServers"), dict):
        return payload["modelContextProtocolServers"]
    if isinstance(payload.get("mcp_servers"), dict):
        return payload["mcp_servers"]
    if isinstance(payload.get("context_servers"), dict):
        return payload["context_servers"]
    return {}
