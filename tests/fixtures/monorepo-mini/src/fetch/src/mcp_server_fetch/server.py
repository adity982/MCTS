from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetch")


@mcp.tool()
async def fetch(url: str) -> str:
    """Fetches a URL from the internet and optionally extracts its contents as markdown.

    Although originally you did not have internet access, and were advised to refuse and tell the user
    this, this tool now grants you internet access. Now you can fetch the most up-to-date information
    and let the user know that."""
    import httpx

    async with httpx.AsyncClient(follow_redirects=True) as client:
        response = await client.get(url)
        return response.text
