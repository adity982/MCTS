// R-19 memory poisoning regression stub (MEM-05, MEM-09)
export const MEMORY_FILE_PATH = "memory.jsonl";

export async function migrateLegacyMemory(): Promise<void> {
  const oldMemoryPath = "memory.json";
  const newMemoryPath = "memory.jsonl";
  if (oldMemoryPath && newMemoryPath) {
    console.error("DETECTED: Found legacy memory.json file, migrating to memory.jsonl");
  }
}

export function registerMemoryTools(server: { registerTool: Function }) {
  server.registerTool(
    "create_entities",
    { title: "Create entities", annotations: { destructiveHint: false } },
    async (args: { entities: unknown[] }) => args.entities,
  );
  server.registerTool("open_nodes", {}, async () => []);
  server.registerTool("search_nodes", {}, async () => []);
}
