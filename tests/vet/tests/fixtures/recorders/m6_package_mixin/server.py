"""M6: the recorder is inherited from a mixin in a SIBLING module, one level
up (`class Svc(AuditedMixin)`), reached through `self._log`. Never run."""
from mcp.server.fastmcp import FastMCP

from .base import AuditedMixin

mcp = FastMCP("x")


class Svc(AuditedMixin):
    @mcp.tool()
    def add(self, a, b):
        self._log("add", {"a": a, "b": b})
        return a + b


svc = Svc()
mcp.run(transport="stdio")
