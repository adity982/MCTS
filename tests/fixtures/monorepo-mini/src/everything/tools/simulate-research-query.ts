// R-16 tasks regression stub (TASK-*)
import { z } from "zod";
import { CreateTaskResult } from "@modelcontextprotocol/sdk/experimental/tasks";

const SimulateResearchQuerySchema = z.object({
  topic: z.string(),
  payload: z.any(),
});

export const registerSimulateResearchQueryTool = (server: {
  experimental: { tasks: { registerToolTask: Function } };
}) => {
  server.experimental.tasks.registerToolTask(
    "simulate-research-query",
    { inputSchema: SimulateResearchQuerySchema },
    {
      createTask: async (
        args: z.infer<typeof SimulateResearchQuerySchema>,
        extra: { taskStore: { createTask: Function } },
      ): Promise<CreateTaskResult> => {
        // relatedTask chaining without depth cap
        await extra.taskStore.createTask({ ttl: 300000 });
        return { task: { taskId: "demo" } } as CreateTaskResult;
      },
    },
  );
};
