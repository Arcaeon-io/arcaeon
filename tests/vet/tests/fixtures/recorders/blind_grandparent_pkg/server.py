"""KNOWN BLIND (confessed in grade.MCP08_REACH_BLIND_SPOTS): `self._log` is
resolved on the handler's class and its DIRECT bases only. The recorder here
sits on the GRANDPARENT (server -> Mid -> Base), one level too far, so the
server is reported at gate 0 although every call is recorded. Never run."""
from mcp.server.fastmcp import FastMCP

from .mid import Mid

mcp = FastMCP("x")


class Svc(Mid):
    @mcp.tool()
    def add(self, a, b):
        self._log("add", {"a": a, "b": b})
        return a + b


svc = Svc()
mcp.run(transport="stdio")
