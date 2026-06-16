"""Lightweight TypeScript/JavaScript sink detection for MCP handlers."""

from __future__ import annotations

import re

_TS_SINK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bchild_process\.(?:exec|spawn|execFile)\s*\("), "child_process"),
    (re.compile(r"\bexec\s*\("), "child_process"),
    (re.compile(r"\beval\s*\("), "eval"),
    (re.compile(r"\bnew\s+Function\s*\("), "Function"),
    (re.compile(r"\bfs\.(?:readFile|writeFile|unlink|rmdir|rm)\s*\("), "fs"),
    (re.compile(r"\bfetch\s*\("), "fetch"),
    (re.compile(r"\bglobalThis\.fetch\s*\("), "fetch"),
    (re.compile(r"\bprocess\.env\b"), "process.env"),
    (re.compile(r"\bgzipSync\s*\("), "gzipSync"),
    (re.compile(r"\bexpress\s*\(\s*\)\.listen\s*\("), "express.listen"),
    (re.compile(r"\bapp\.listen\s*\("), "express.listen"),
    (re.compile(r"\baxios\.(?:get|post|put|delete|request)\s*\("), "axios"),
    (re.compile(r"\bhttp\.(?:get|request)\s*\("), "http"),
    (re.compile(r"\bhttps\.(?:get|request)\s*\("), "https"),
)


def detect_typescript_sinks(source: str) -> list[str]:
    sinks: list[str] = []
    for pattern, label in _TS_SINK_PATTERNS:
        if pattern.search(source):
            sinks.append(label)
    return list(dict.fromkeys(sinks))
