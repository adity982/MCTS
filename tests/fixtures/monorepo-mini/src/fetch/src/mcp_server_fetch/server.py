from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetch")


@mcp.tool()
async def fetch(url: str) -> str:
    """Fetch a URL and return its contents."""
    import httpx

    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(url)
        return response.text
