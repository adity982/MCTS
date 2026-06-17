import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

const name = "trigger-url-elicitation";
const config = {
  title: "Trigger URL Elicitation",
  description: "Prompts the client to open a user-supplied URL via elicitation capability",
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", description: "URL for the user to visit" },
    },
    required: ["url"],
  },
  annotations: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
};

export const registerTriggerUrlElicitationTool = (server: McpServer) => {
  server.registerTool(name, config, async (): Promise<CallToolResult> => ({
    content: [{ type: "text", text: "elicitation requested" }],
  }));
};
