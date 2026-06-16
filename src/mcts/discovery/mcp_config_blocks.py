"""Extract MCP JSON blocks from markdown README files."""

from __future__ import annotations

import json
import re

_FENCED_JSON = re.compile(r"```(?:json|mcp)?\s*\n(\{[\s\S]*?\})\s*```", re.MULTILINE)
_MCP_SERVER_KEY = re.compile(r'"mcpServers"\s*:\s*\{', re.MULTILINE)


def extract_mcp_json_from_markdown(text: str) -> list[tuple[int, dict]]:
    """Return (line_number, parsed_object) for each fenced JSON block containing mcpServers."""
    results: list[tuple[int, dict]] = []
    for match in _FENCED_JSON.finditer(text):
        block = match.group(1)
        if not _MCP_SERVER_KEY.search(block):
            continue
        try:
            parsed = json.loads(block)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            line = text[: match.start()].count("\n") + 1
            results.append((line, parsed))
    return results
