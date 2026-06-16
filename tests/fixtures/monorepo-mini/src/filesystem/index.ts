// R-10 / R-18 filesystem regression stubs (SYM-02, FS-01)
import fs from "fs/promises";
import path from "path";

export async function listDirectoryWithSizes(validPath: string) {
  const entries = await fs.readdir(validPath, { withFileTypes: true });
  return Promise.all(
    entries.map(async (entry) => {
      const entryPath = path.join(validPath, entry.name);
      const stats = await fs.stat(entryPath);
      return { name: entry.name, size: stats.size };
    }),
  );
}

export function registerReadMultipleFiles(server: { registerTool: Function }) {
  server.registerTool(
    "read_multiple_files",
    {
      title: "Read Multiple Files",
      inputSchema: {
        paths: { type: "array", items: { type: "string" } },
      },
    },
    async (args: { paths: string[] }) => args.paths,
  );
}
