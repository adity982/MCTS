"""CLI tests for mcts inventory privacy controls."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcts.cli.main import app

runner = CliRunner()


def test_cli_paths_only_with_config_path(tmp_path: Path) -> None:
    config = tmp_path / "team.json"
    config.write_text(json.dumps({"mcpServers": {"hidden": {"command": "node"}}}))

    result = runner.invoke(app, ["inventory", "--paths-only", "--config-path", str(config)])

    assert result.exit_code == 0
    assert "hidden" not in result.stdout
    assert "team.json" in result.stdout


def test_cli_paths_only_conflicts_with_scan(tmp_path: Path) -> None:
    config = tmp_path / "team.json"
    config.write_text(json.dumps({"mcpServers": {"demo": {"command": "node"}}}))

    result = runner.invoke(
        app,
        ["inventory", "--paths-only", "--scan", "--config-path", str(config)],
    )

    assert result.exit_code == 2
    assert "--paths-only cannot be combined" in result.stdout


def test_cli_paths_only_rejects_output(tmp_path: Path) -> None:
    config = tmp_path / "team.json"
    config.write_text(json.dumps({"mcpServers": {"demo": {"command": "node"}}}))
    output = tmp_path / "out.json"

    result = runner.invoke(
        app,
        ["inventory", "--paths-only", "--config-path", str(config), "-o", str(output)],
    )

    assert result.exit_code == 2
    assert "does not support --output" in result.stdout


def test_cli_redact_paths_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    config = fake_home / ".cursor" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"mcpServers": {"myserver": {"command": "node", "args": ["server.js"]}}}))
    output = tmp_path / "inventory.json"

    result = runner.invoke(
        app,
        [
            "inventory",
            "--config-path",
            str(config),
            "--redact-paths",
            "-o",
            str(output),
            "--theme",
            "minimal",
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    entry = payload["entries"][0]
    assert entry["config_path"] == "~/.cursor/mcp.json"
    assert "confing_path" not in entry
