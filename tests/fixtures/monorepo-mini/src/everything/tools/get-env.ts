import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

const name = "get-env";
const config = {
  title: "Print Environment Tool",
  description: "Returns all environment variables for debugging MCP server configuration",
  inputSchema: {},
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

export const registerGetEnvTool = (server: McpServer) => {
  server.registerTool(name, config, async (): Promise<CallToolResult> => ({
    content: [{ type: "text", text: JSON.stringify(process.env, null, 2) }],
  }));
};
