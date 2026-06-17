# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security issue in MCTS itself:

1. Email or DM the maintainers (update this with your contact when published)
2. Include steps to reproduce and potential impact
3. Allow up to 90 days for remediation before public disclosure

We appreciate responsible disclosure and will acknowledge reporters in the release notes when appropriate.

## Scope

- MCTS CLI, libraries, GitHub Action, and official documentation
- Out of scope: vulnerabilities in third-party MCP servers scanned by MCTS (report those to the server maintainers)

## Safe Usage

MCTS is a security analysis tool. Only scan MCP servers you own or have explicit authorization to test.

- Live probing and fuzzing start subprocesses — see [Live Scanning](docs/scanning/live-scanning.md) and [Protocol Fuzzing](docs/scanning/fuzzing.md) for consent requirements
- CI usage: [CI Integration](docs/platform/ci-integration.md)
- REST API: set `MCTS_API_KEY` for production; see [REST API threat model](docs/platform/rest-api.md#threat-model)

HTML reports are self-contained files with embedded scan data and vendored chart assets. They do not transmit data to MCTS or third parties when you open the file in a browser.

## Inventory Privacy

`mcts inventory` discovers MCP configuration files in well-known locations
(Cursor, Claude Desktop, VS Code, Windsurf, Gemini, Codex, and others). This is
a **read-only** operation — no data is sent externally, no files are modified,
and environment variable **values** are not exported (only key names when parsing
configs).

To limit exposure on shared or sensitive machines:

- `--paths-only` — list config file locations without parsing server details
- `--config-path <file>` — scope discovery to a single explicit file
- `--redact-paths` — replace home directory with `~` in inventory entry and
  skill paths in terminal output and default inventory JSON (`-o inventory.json`)

`--redact-paths` does not redact paths inside nested scan reports produced by
`--scan-all`. Treat exported inventory JSON like any config audit artifact.

In CI environments, ephemeral runners typically have no MCP configs and inventory
will report zero entries.

## Documentation

- [Documentation index](docs/index.md)
- [Architecture](docs/analysis/architecture.md)
