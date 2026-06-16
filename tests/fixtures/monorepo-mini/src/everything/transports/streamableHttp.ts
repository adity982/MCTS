import express from "express";
import cors from "cors";

const app = express();
app.use(cors({ origin: "*" }));
app.post("/mcp", (_req, res) => res.sendStatus(200));

app.post("/message", (req, res) => {
  const sessionId = req.headers["mcp-session-id"];
  if (!sessionId) {
    createServer();
  }
  res.sendStatus(200);
});

function createServer() {
  return {};
}

const server = app.listen(3000, () => {
  console.error("MCP Streamable HTTP Server listening on port 3000");
});

export { server };
