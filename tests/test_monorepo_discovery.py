"""Tests for monorepo discovery and full-surface expansion."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.discovery.monorepo import (
    collect_surface_files,
    discover_monorepo,
    discover_monorepo_packages,
    expand_static_surface,
)
from mcts.discovery.static_runner import discover_static
from mcts.sast.python.taint import analyze_handler_taint

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "monorepo-mini"
SERVERS_ROOT = Path("/Users/arghyadeep_nfal/CODE_ARGS/servers")


def test_discover_monorepo_packages_finds_two_packages() -> None:
    packages = discover_monorepo_packages(FIXTURE_ROOT)
    names = {pkg.name for pkg in packages}
    assert "fetch" in names
    assert "everything" in names


def test_expand_static_surface_includes_transports() -> None:
    pkg = FIXTURE_ROOT / "src" / "everything"
    config = ScanConfig(target=pkg, surface_depth="full", languages=["typescript"])
    info = expand_static_surface(pkg, config)
    paths = " ".join(info.source_files)
    assert "transports" in paths
    assert "tools" in paths


def test_monorepo_scan_merges_tools() -> None:
    config = ScanConfig(
        target=FIXTURE_ROOT,
        monorepo=True,
        aggregate=True,
        surface_depth="full",
        languages=["python", "typescript"],
    )
    info = discover_monorepo(config)
    tool_names = {tool.name for tool in info.tools}
    assert "fetch" in tool_names
    assert "get-env" in tool_names
    assert len(info.source_files) >= 4


def test_discover_static_monorepo_flag() -> None:
    config = ScanConfig(
        target=FIXTURE_ROOT,
        monorepo=True,
        aggregate=True,
        languages=["python", "typescript"],
    )
    info = discover_static(config)
    assert info.discovery_mode.startswith("monorepo")


def test_httpx_sink_registered() -> None:
    source = """
async def handler(url: str):
    async with httpx.AsyncClient(follow_redirects=True) as client:
        return await client.get(url)
"""
    result = analyze_handler_taint(source)
    assert "http_client" in result.sinks


def test_collect_surface_files_python_entrypoints() -> None:
    pkg = FIXTURE_ROOT / "src" / "fetch"
    config = ScanConfig(target=pkg, surface_depth="full")
    files = collect_surface_files(pkg, config)
    assert any(path.endswith("__init__.py") for path in files)


def test_mini_monorepo_scan_finds_network_and_transport_signals() -> None:
    report = Scanner(
        ScanConfig(
            target=FIXTURE_ROOT,
            monorepo=True,
            aggregate=True,
            surface_depth="full",
            languages=["python", "typescript"],
            enable_attack_chains=False,
        )
    ).run()
    analyzers = {finding.analyzer for finding in report.findings}
    assert "behavioral_static" in analyzers or "static_signals" in analyzers
    assert len(report.server.tools) >= 2


def test_js_const_name_register_tool_pattern() -> None:
    from mcts.discovery.static_js import parse_js_tools_from_content

    content = """
const name = "get-env";
const config = { description: "Returns environment variables", inputSchema: {} };
export const registerGetEnvTool = (server) => {
  server.registerTool(name, config, async () => ({ content: [] }));
};
"""
    tools = parse_js_tools_from_content(Path("get-env.ts"), content)
    assert any(tool.name == "get-env" for tool in tools)


def test_python_enum_tool_pattern() -> None:
    from mcts.discovery.static import parse_python_tools_from_content

    content = """
class GitTools(str, Enum):
    STATUS = "git_status"
    COMMIT = "git_commit"

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name=GitTools.STATUS,
            description="Shows status",
        ),
    ]
"""
    tools = parse_python_tools_from_content(Path("server.py"), content)
    assert "git_status" in {tool.name for tool in tools}


@pytest.mark.integration
@pytest.mark.skipif(not SERVERS_ROOT.is_dir(), reason="MCP servers corpus not available")
def test_servers_everything_discovers_get_env() -> None:
    from mcts.discovery.static_runner import discover_static

    info = discover_static(
        ScanConfig(
            target=SERVERS_ROOT / "src" / "everything",
            package_depth="full",
            languages=["typescript"],
        )
    )
    assert "get-env" in {tool.name for tool in info.tools}


@pytest.mark.integration
@pytest.mark.skipif(not SERVERS_ROOT.is_dir(), reason="MCP servers corpus not available")
def test_servers_git_discovers_tools_and_auth01() -> None:
    report = Scanner(
        ScanConfig(
            target=SERVERS_ROOT / "src" / "git",
            package_depth="full",
            languages=["python"],
            enable_attack_chains=False,
        )
    ).run()
    assert len(report.server.tools) >= 10
    auth = [f for f in report.findings if f.analyzer == "scoping" and f.evidence.get("rule_id") == "AUTH-01"]
    assert auth
    assert report.score_v2 is not None and report.score_v2.security_score < 100


@pytest.mark.integration
@pytest.mark.skipif(not SERVERS_ROOT.is_dir(), reason="MCP servers corpus not available")
def test_servers_monorepo_regression_r21() -> None:
    report = Scanner(
        ScanConfig(
            target=SERVERS_ROOT,
            monorepo=True,
            aggregate=True,
            surface_depth="full",
            languages=["python", "typescript"],
            enable_attack_chains=False,
        )
    ).run()
    assert len(report.server.tools) >= 10
    assert len(report.server.source_files) >= 20
    analyzers = {finding.analyzer for finding in report.findings}
    assert analyzers
