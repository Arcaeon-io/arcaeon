"""Genuine gate 0 wearing every 0.0.17 shape at once: a bare decorator, a
context manager, a `self.` method, a registered middleware, a wrapped
dispatcher. None of them records anything, so following them must not buy the
server a gate. Fixture for test_recorder_shapes.py; never run."""
import contextlib
import functools
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("x")


def timed(fn):
    @functools.wraps(fn)
    def inner(*a, **k):
        t0 = time.time()
        try:
            return fn(*a, **k)
        finally:
            print("took", time.time() - t0)
    return inner


@contextlib.contextmanager
def quiet():
    yield


class Cors:
    async def on_request(self, context, call_next):
        return await call_next(context)


def _retrying(dispatch):
    async def inner(name, arguments):
        for _ in range(3):
            try:
                return await dispatch(name, arguments)
            except ConnectionError:
                continue
        raise ConnectionError(name)
    return inner


class Svc:
    def _validate(self, a):
        if a is None:
            raise ValueError("a")

    @mcp.tool()
    @timed
    def add(self, a, b):
        self._validate(a)
        with quiet():
            return a + b


mcp.add_middleware(Cors())
mcp.call_tool = _retrying(mcp.call_tool)
mcp.run(transport="stdio")
