# R-21 — Monorepo aggregate regression

Source corpus: [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) (`src/*` packages).

Scan command (target state):

```bash
mcts scan ./servers --monorepo --surface-depth full --aggregate
```

Mini fixture used in CI: `tests/fixtures/monorepo-mini/`.

Expected: tools from fetch, git, and everything packages; not supply-chain-only findings.
