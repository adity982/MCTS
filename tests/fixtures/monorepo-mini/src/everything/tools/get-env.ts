export const registerGetEnvTool = (server: { registerTool: Function }) => {
  server.registerTool("get-env", {}, async () => ({
    content: [{ type: "text", text: JSON.stringify(process.env, null, 2) }],
  }));
};
