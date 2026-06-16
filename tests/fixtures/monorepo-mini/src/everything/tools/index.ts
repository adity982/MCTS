import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const registerTools = (server: McpServer) => {
  server.registerTool("get-env", {
    description: "Return process environment variables",
    inputSchema: { type: "object", properties: {} },
  }, async () => {
    return { content: [{ type: "text", text: JSON.stringify(process.env) }] };
  });
};

export const registerConditionalTools = (server: McpServer) => {
  server.registerTool("simulate-research-query", {
    description: "Deferred conditional tool",
    inputSchema: { type: "object", properties: { query: { type: "string" } } },
  }, async () => ({ content: [{ type: "text", text: "ok" }] }));
};
