"""Monorepo package discovery and full-surface expansion (DISC-01–07)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.target import ScanTarget
from mcts.discovery.instruction_files import discover_instruction_surfaces
from mcts.discovery.static import StaticDiscovery, parse_python_tools_from_content
from mcts.discovery.static_js import JsStaticDiscovery, parse_js_tools_from_content
from mcts.discovery.static_merge import merge_static_server_info
from mcts.mcp.models import MCPPrompt, MCPServerInfo, MCPTool

SURFACE_GLOBS = [
    "**/index.ts",
    "**/tools/**/*.ts",
    "**/transports/**/*.ts",
    "**/resources/**/*.ts",
    "**/prompts/**/*.ts",
    "**/server/**/*.ts",
]

PYTHON_SURFACE_NAMES = frozenset({"server.py", "__init__.py", "__main__.py"})

TEST_SURFACE_GLOBS = [
    "**/__tests__/**/*.ts",
    "**/*.test.ts",
    "**/*.test.tsx",
    "**/test_*.py",
]

README_MCP_BLOCK = re.compile(
    r"```(?:json|mcp)?\s*\n(\{[\s\S]*?\"mcpServers\"[\s\S]*?\})\s*```",
    re.MULTILINE,
)

PACKAGE_MARKERS = ("package.json", "pyproject.toml")


@dataclass(frozen=True)
class MonorepoPackage:
    """One publishable MCP server package within a monorepo."""

    name: str
    root: Path

    @property
    def scan_target(self) -> ScanTarget:
        return ScanTarget(self.root)


def discover_monorepo_packages(root: Path) -> list[MonorepoPackage]:
    """Return one package per directory under src/*/ with package.json or pyproject.toml."""
    root = root.expanduser().resolve()
    packages: list[MonorepoPackage] = []

    search_roots: list[Path] = []
    src_dir = root / "src"
    if src_dir.is_dir():
        search_roots.extend(sorted(p for p in src_dir.iterdir() if p.is_dir()))
    if not search_roots:
        search_roots.extend(sorted(p for p in root.iterdir() if p.is_dir()))

    seen: set[Path] = set()
    for candidate in search_roots:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        if _is_mcp_package(candidate):
            packages.append(MonorepoPackage(name=candidate.name, root=candidate))
            seen.add(resolved)

    if not packages and _is_mcp_package(root):
        packages.append(MonorepoPackage(name=root.name, root=root))
    return packages


def expand_static_surface(pkg_root: Path, config: ScanConfig) -> MCPServerInfo:
    """Union discovery across entrypoints, tools, transports, prompts, and related surfaces."""
    pkg_config = config.model_copy(update={"target": pkg_root})
    langs = {language.lower() for language in config.languages}
    parts: list[MCPServerInfo] = []

    if "python" in langs:
        parts.append(StaticDiscovery(pkg_config).discover())
    if any(lang in langs for lang in ("typescript", "javascript", "js")):
        parts.append(JsStaticDiscovery(pkg_config).discover())
    parts.append(discover_instruction_surfaces(pkg_config))

    if not parts:
        base = MCPServerInfo(name=pkg_root.name, discovery_mode="empty")
    else:
        base = merge_static_server_info(*parts)

    if _full_surface(config):
        surface_files = collect_surface_files(pkg_root, config)
        merged_files = dict(base.source_files)
        merged_files.update(surface_files)
        prompts = list(base.prompts)
        prompts.extend(_prompts_from_surface_files(surface_files))
        transport = _infer_transport(merged_files)
        tools = _merge_tools(base.tools, _tools_from_surface_files(merged_files, langs))
        return base.model_copy(
            update={
                "source_files": merged_files,
                "tools": tools,
                "prompts": _dedupe_prompts(prompts),
                "transport": transport,
                "discovery_mode": "static+full-surface",
            }
        )
    return base


def discover_monorepo(config: ScanConfig) -> MCPServerInfo:
    """Discover and optionally aggregate all MCP packages in a monorepo root."""
    root = Path(config.target).expanduser().resolve()
    packages = discover_monorepo_packages(root)
    if not packages:
        return MCPServerInfo(name=root.name, discovery_mode="empty")

    infos = [expand_static_surface(pkg.root, config) for pkg in packages]
    if config.aggregate or len(infos) == 1:
        merged = merge_static_server_info(*infos)
        return merged.model_copy(
            update={
                "name": root.name,
                "discovery_mode": "monorepo+aggregate" if config.aggregate else merged.discovery_mode,
            }
        )
    return merge_static_server_info(*infos)


def collect_surface_files(root: Path, config: ScanConfig) -> dict[str, str]:
    """Collect full surface union for Semgrep and behavioral analyzers."""
    files: dict[str, str] = {}
    globs = list(SURFACE_GLOBS)
    if config.include_test_surfaces:
        globs.extend(TEST_SURFACE_GLOBS)

    for pattern in globs:
        for path in sorted(root.glob(pattern)):
            if not _should_include_file(path, root, config):
                continue
            content = _read_file(path, config.max_file_bytes)
            if content:
                files[str(path.resolve())] = content

    for name in PYTHON_SURFACE_NAMES:
        for path in sorted(root.rglob(name)):
            if not _should_include_file(path, root, config):
                continue
            content = _read_file(path, config.max_file_bytes)
            if content:
                files[str(path.resolve())] = content

    for dockerfile in sorted(root.rglob("Dockerfile*")):
        if dockerfile.is_file() and _should_include_file(dockerfile, root, config):
            content = _read_file(dockerfile, config.max_file_bytes)
            if content:
                files[str(dockerfile.resolve())] = content

    for readme in sorted(root.rglob("README*.md")):
        if readme.is_file() and _should_include_file(readme, root, config):
            content = _read_file(readme, config.max_file_bytes)
            if content:
                key = str(readme.resolve())
                files[key] = content
                for match in README_MCP_BLOCK.finditer(content):
                    block = match.group(1).strip()
                    if block:
                        files[f"{key}#mcp-block"] = block

    return files


def _full_surface(config: ScanConfig) -> bool:
    depth = (config.surface_depth or "").lower()
    pkg_depth = (config.package_depth or "").lower()
    return depth == "full" or pkg_depth == "full" or config.monorepo


def _is_mcp_package(path: Path) -> bool:
    return any((path / marker).is_file() for marker in PACKAGE_MARKERS)


def _should_include_file(path: Path, root: Path, config: ScanConfig) -> bool:
    if not path.is_file():
        return False
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    rel_str = str(rel)
    if any(part in config.exclude_dirs for part in rel.parts):
        return False
    if config.exclude_globs and any(fnmatch(rel_str, g) for g in config.exclude_globs):
        return False
    if not config.include_test_surfaces and _is_test_path(rel.parts):
        return False
    try:
        if path.stat().st_size > config.max_file_bytes:
            return False
    except OSError:
        return False
    return True


def _is_test_path(parts: tuple[str, ...]) -> bool:
    lowered = {part.lower() for part in parts}
    return bool(lowered & {"tests", "test", "__tests__"})


def _read_file(path: Path, max_bytes: int) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _infer_transport(source_files: dict[str, str]) -> str:
    for path, content in source_files.items():
        if "/transports/" in path.replace("\\", "/") or "transports" in Path(path).parts:
            if "streamableHttp" in content or "streamable-http" in content.lower():
                return "streamable-http"
            if "sse.ts" in path or "SSEServerTransport" in content:
                return "sse"
            if "express" in content and "listen" in content:
                return "http"
    return "stdio"


def _prompts_from_surface_files(source_files: dict[str, str]) -> list[MCPPrompt]:
    prompts: list[MCPPrompt] = []
    for path, content in source_files.items():
        if "/prompts/" not in path.replace("\\", "/") and "prompts" not in Path(path).parts:
            continue
        if not content.strip():
            continue
        name = Path(path).stem
        prompts.append(
            MCPPrompt(
                name=name,
                description="",
                source_file=path,
                discovered_via="static-surface",
            )
        )
    return prompts


def _dedupe_prompts(prompts: list[MCPPrompt]) -> list[MCPPrompt]:
    by_key: dict[tuple[str, str | None], MCPPrompt] = {}
    for prompt in prompts:
        by_key[(prompt.name, prompt.source_file)] = prompt
    return list(by_key.values())


def _tools_from_surface_files(source_files: dict[str, str], langs: set[str]) -> list[MCPTool]:
    """Parse tools from every file in the full-surface union (DISC-01/03)."""
    tools: list[MCPTool] = []
    for path, content in source_files.items():
        if not content or path.endswith("#mcp-block"):
            continue
        file_path = Path(path)
        suffix = file_path.suffix.lower()
        if suffix == ".py" and "python" in langs:
            tools.extend(parse_python_tools_from_content(file_path, content))
        elif suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"} and langs & {
            "typescript",
            "javascript",
            "js",
        }:
            tools.extend(parse_js_tools_from_content(file_path, content))
    return tools


def _merge_tools(existing: list[MCPTool], extra: list[MCPTool]) -> list[MCPTool]:
    by_name: dict[str, MCPTool] = {tool.name: tool for tool in existing}
    for tool in extra:
        current = by_name.get(tool.name)
        if current is None or _tool_richness(tool) > _tool_richness(current):
            by_name[tool.name] = tool
    return list(by_name.values())


def _tool_richness(tool: MCPTool) -> int:
    score = len(tool.input_schema.get("properties", {}))
    score += 2 if tool.description else 0
    score += 2 if tool.handler_snippet else 0
    score += 1 if tool.source_file else 0
    return score
