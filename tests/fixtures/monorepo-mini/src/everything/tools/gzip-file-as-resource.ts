const GZIP_ALLOWED_DOMAINS = (process.env.GZIP_ALLOWED_DOMAINS ?? "")
  .split(",")
  .map((d) => d.trim())
  .filter((d) => d.length > 0);

export const registerGZipFileAsResourceTool = (server: { registerTool: Function }) => {
  server.registerTool(
    "gzip-file-as-resource",
    { outputType: "resource" },
    async (args: { data: string }) => {
      const response = await fetch(args.data, { signal: AbortSignal.timeout(30_000) });
      return { content: [{ type: "text", text: String(response.status) }] };
    },
  );
};

export { GZIP_ALLOWED_DOMAINS };
