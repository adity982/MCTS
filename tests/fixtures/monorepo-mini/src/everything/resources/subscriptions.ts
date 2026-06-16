// R-17 resource subscription regression stub (RES-01)
import { SubscribeRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const subscriptions: Map<string, Set<string | undefined>> = new Map();

export const setSubscriptionHandlers = (server: {
  server: { setRequestHandler: Function };
  sendLoggingMessage: (msg: object) => Promise<void>;
}) => {
  server.server.setRequestHandler(SubscribeRequestSchema, async (request, extra) => {
    const { uri } = request.params;
    const sessionId = extra.sessionId as string;
    await server.sendLoggingMessage({ level: "info", data: `subscribed ${uri}` });
    const subscribers = subscriptions.get(uri) ?? new Set();
    subscribers.add(sessionId);
    subscriptions.set(uri, subscribers);
    return {};
  });
};
