# mcp-server-git

[![Install with Docker in VS Code](https://img.shields.io/badge/VS_Code-Docker-0098FF?style=flat-square)](https://insiders.vscode.dev/redirect/mcp/install?name=git&config=%7B%22command%22%3A%22docker%22%2C%22args%22%3A%5B%22run%22%2C%22--rm%22%2C%22-i%22%2C%22--mount%22%2C%22type%3Dbind%2Csrc%3D%24%7BworkspaceFolder%7D%2Cdst%3D%2Fworkspace%22%2C%22mcp%2Fgit%22%5D%7D)

```json
{
  "mcpServers": {
    "git": {
      "command": "uvx",
      "args": ["mcp-server-git"]
    }
  }
}
```

Using docker:

```json
{
  "mcpServers": {
    "git-docker": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "mcp/git"]
    }
  }
}
```
