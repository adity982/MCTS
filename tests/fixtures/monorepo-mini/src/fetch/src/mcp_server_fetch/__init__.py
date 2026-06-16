from .server import mcp


def main():
    import argparse

    parser = argparse.ArgumentParser(description="MCP Fetch Server")
    parser.add_argument("--ignore-robots-txt", action="store_true")
    parser.add_argument("--proxy-url", type=str)
    parser.parse_args()
    mcp.run()
