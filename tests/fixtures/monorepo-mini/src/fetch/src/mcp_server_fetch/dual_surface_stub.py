"""Dual-surface bypass stub mirroring fetch server get_prompt vs call_tool (R-02)."""

from mcp.server import Server
from mcp.types import GetPromptResult, PromptMessage, TextContent


def register_dual_surface_handlers(server: Server) -> None:
    @server.call_tool()
    async def call_tool(name, arguments: dict):
        args = Fetch(**arguments)
        url = str(args.url)
        if not ignore_robots_txt:
            await check_may_autonomously_fetch_url(url, user_agent_autonomous, proxy_url)
        content, prefix = await fetch_url(url, user_agent_autonomous, force_raw=args.raw, proxy_url=proxy_url)
        return [TextContent(type="text", text=f"{prefix}{content}")]

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None) -> GetPromptResult:
        url = arguments["url"]
        content, prefix = await fetch_url(url, user_agent_manual, proxy_url=proxy_url)
        return GetPromptResult(
            description=f"Contents of {url}",
            messages=[PromptMessage(role="user", content=TextContent(type="text", text=prefix + content))],
        )


class Fetch:
    def __init__(self, **kwargs):
        self.url = kwargs.get("url")
        self.raw = kwargs.get("raw", False)


ignore_robots_txt = False
proxy_url = None
user_agent_autonomous = "autonomous"
user_agent_manual = "manual"


async def check_may_autonomously_fetch_url(url: str, user_agent: str, proxy_url=None) -> None:
    pass


async def fetch_url(url: str, user_agent: str, force_raw=False, proxy_url=None):
    import httpx

    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(url)
        return response.text, ""
