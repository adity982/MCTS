"""Scanner integration for attack graph v3."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner
from mcts.mcp.models import MCPServerInfo, MCPTool

MONOREPO_MINI = Path("tests/fixtures/monorepo-mini")
REGRESSION = Path("tests/fixtures/regression")

MVP_TEMPLATE_FIXTURES = {
    "R-01-net-fetch": "SSRF_EXFIL",
    "R-06-transport-everything": "HTTP_TAKEOVER",
    "R-11-memory-readme": "MEMORY_POISON",
    "R-19-memory-poison": "MEMORY_POISON",
}


def test_scanner_emits_v3_attack_graph(tmp_path: Path) -> None:
    server_py = tmp_path / "server.py"
    content = "import httpx\nasync def fetch(url):\n    return httpx.get(url, follow_redirects=True)\n"
    server_py.write_text(content, encoding="utf-8")
    config = ScanConfig(target=tmp_path, attack_graph_version=3, attack_graph_legacy_chains=False)
    scanner = Scanner(config)
    scanner.analyzers = [a for a in scanner.analyzers if getattr(a, "name", None) != "attack_chains"]
    server = MCPServerInfo(
        name="fetch",
        source_files={"server.py": content},
        tools=[MCPTool(name="fetch", description="fetch", handler_snippet=content)],
    )
    report = scanner.analyze_server(server)
    assert report.attack_graph.get("version") == 3
    assert report.attack_graph.get("edges")


def test_v3_config_enables_graph_builder() -> None:
    config = ScanConfig(target=".", attack_graph_version=3)
    assert config.attack_graph_version == 3
    assert config.attack_graph_legacy_chains is False


@pytest.mark.parametrize(("fixture_id", "template_id"), MVP_TEMPLATE_FIXTURES.items())
def test_mvp_template_matches_regression_fixture(fixture_id: str, template_id: str) -> None:
    spec = json.loads((REGRESSION / fixture_id / "expected.json").read_text(encoding="utf-8"))
    target = MONOREPO_MINI / spec["servers_path"]
    config = ScanConfig(
        target=str(target),
        surface_depth="full",
        attack_graph_version=3,
        attack_graph_legacy_chains=False,
    )
    report = Scanner(config).run()
    matched = set(report.attack_graph.get("templates_matched") or [])
    assert template_id in matched
