"""Tests for config inventory and cross-server analysis."""

from __future__ import annotations

import json
from pathlib import Path

from mcts.analyzers.cross_server import CrossServerAnalyzer
from mcts.inventory.discoverers import parse_config_file
from mcts.inventory.models import InventoryEntry
from mcts.taxonomy.mapper import enrich_findings, load_taxonomy


def test_parse_cursor_config(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "alpha": {"command": "uv", "args": ["run", "server.py"]},
                    "beta": {"command": "uv", "args": ["run", "server.py"]},
                }
            }
        )
    )
    entries = parse_config_file("cursor", config)
    assert len(entries) == 2
    assert entries[0].server_name in {"alpha", "beta"}


def test_cross_server_detects_name_collision() -> None:
    inventory = [
        InventoryEntry(client="cursor", config_path="/a", server_name="s1", tools=["read_file"]),
        InventoryEntry(client="claude", config_path="/b", server_name="s2", tools=["read_file"]),
    ]
    findings = CrossServerAnalyzer(inventory).analyze_inventory(inventory)
    assert findings
    assert findings[0].technique_id == "MCTS-T-1008"


def test_taxonomy_enriches_findings() -> None:
    from mcts.reporting.models import Finding, Severity

    finding = Finding(
        id="x",
        analyzer="command_execution",
        title="t",
        description="d",
        severity=Severity.CRITICAL,
        recommendation="r",
    )
    enriched = enrich_findings([finding])[0]
    assert enriched.technique_id == "MCTS-T-1003"
    assert enriched.cwe_id == "CWE-78"
    assert enriched.mitigation_ids


def test_taxonomy_catalog_loads() -> None:
    data = load_taxonomy()
    assert "MCTS-T-1001" in data["techniques"]
    assert data["mitigations"]


def test_redact_home() -> None:
    from mcts.inventory.discoverers import redact_home

    home = str(Path.home())
    assert redact_home(f"{home}/.cursor/mcp.json") == "~/.cursor/mcp.json"
    assert redact_home("/other/path") == "/other/path"


def test_redact_home_resolves_before_prefix() -> None:
    from mcts.inventory.discoverers import redact_home

    home = Path.home().resolve()
    target = home / ".cursor" / "mcp.json"
    assert redact_home(str(target)) == "~/.cursor/mcp.json"


def test_redact_entry_dict_replaces_config_path() -> None:
    from mcts.inventory.discoverers import redact_entry_dict

    home = str(Path.home())
    raw = {"config_path": f"{home}/.cursor/mcp.json", "server_name": "demo"}
    redacted = redact_entry_dict(raw, redact=True)
    assert redacted["config_path"] == "~/.cursor/mcp.json"
    assert "confing_path" not in redacted


def test_config_path_scopes_to_single_file(tmp_path: Path) -> None:
    config = tmp_path / "custom.json"
    config.write_text(json.dumps({"mcpServers": {"myserver": {"command": "node", "args": ["server.js"]}}}))
    from mcts.inventory.runner import run_inventory

    report = run_inventory(config_path=config)
    assert len(report.entries) == 1
    assert report.entries[0].server_name == "myserver"
    assert report.clients_scanned == ["user"]
    assert report.config_files_found == 1


def test_config_path_sets_config_files_found_for_empty_parse(tmp_path: Path) -> None:
    config = tmp_path / "empty.json"
    config.write_text(json.dumps({"other": []}))
    from mcts.inventory.runner import run_inventory

    report = run_inventory(config_path=config)
    assert report.entries == []
    assert report.config_files_found == 1


def test_config_path_with_skills(tmp_path: Path, monkeypatch) -> None:
    config = tmp_path / "custom.json"
    config.write_text(json.dumps({"mcpServers": {"myserver": {"command": "node"}}}))
    skill_dir = tmp_path / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Demo skill\n")
    monkeypatch.chdir(tmp_path)

    from mcts.inventory.runner import run_inventory

    report = run_inventory(config_path=config, skills=True, skills_dirs=[tmp_path / "skills"])
    assert report.config_files_found == 1
    assert report.skills


def test_config_path_missing_file_returns_empty(tmp_path: Path) -> None:
    from mcts.inventory.runner import run_inventory

    report = run_inventory(config_path=tmp_path / "nope.json")
    assert report.entries == []
    assert report.config_files_found == 0


def test_run_inventory_scan_all_respects_config_path(tmp_path: Path) -> None:
    config = tmp_path / "custom.json"
    config.write_text(json.dumps({"mcpServers": {"myserver": {"command": "node", "args": ["server.js"]}}}))
    from mcts.core.config import ScanConfig
    from mcts.inventory.scan_all import run_inventory_scan_all

    report, rows = run_inventory_scan_all(ScanConfig(target=Path(".")), config_path=config)
    assert report.config_files_found == 1
    assert len(report.entries) == 1
    assert report.entries[0].server_name == "myserver"
    assert len(rows) == 1
    assert rows[0]["server_name"] == "myserver"
