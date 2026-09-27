"""Shared fixtures for the framework adapter tests (lane B).

`served` starts a real loopback `arcaeon serve` (make_server + run on a
thread, port 0, a token, a served root under tmp_path) and stops it when the
test ends. Every adapter test drives its tools against this server through
arcaeon.client.Client, with a fake framework module in sys.modules, never the
real framework.
"""
from __future__ import annotations

import io
import sys
import threading
import types

import pytest

from arcaeon.client import Client
from arcaeon.serve import server as S

TOKEN = "adapter-test-token"


@pytest.fixture()
def served(tmp_path, monkeypatch):
    home = tmp_path / "arcaeon-home"
    monkeypatch.setenv("ARCAEON_HOME", str(home))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    root = tmp_path / "served"
    root.mkdir()
    monkeypatch.chdir(tmp_path)
    server = S.make_server(port=0, token=TOKEN, root=root)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    try:
        yield types.SimpleNamespace(server=server, root=root,
                                    client=Client(url=server.url, token=TOKEN))
    finally:
        server.shutdown()
        t.join(10)
        assert not t.is_alive()


@pytest.fixture()
def fake_module(monkeypatch):
    """Install a fake module (and its parents) in sys.modules for one test."""
    def install(name: str, **attrs) -> types.ModuleType:
        parts = name.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[:i])
            if parent not in sys.modules or not getattr(sys.modules[parent], "_arcaeon_fake", False):
                pm = types.ModuleType(parent)
                pm._arcaeon_fake = True
                monkeypatch.setitem(sys.modules, parent, pm)
        mod = types.ModuleType(name)
        mod._arcaeon_fake = True
        for k, v in attrs.items():
            setattr(mod, k, v)
        monkeypatch.setitem(sys.modules, name, mod)
        if len(parts) > 1:
            setattr(sys.modules[".".join(parts[:-1])], parts[-1], mod)
        return mod
    return install


class _FakeFieldInfo:
    def __init__(self, default, description=None):
        self.default, self.description = default, description


def _fake_create_model(name, **fields):
    """Enough of pydantic.create_model for the adapter tests: a class whose
    model_json_schema() lists the properties and the required ones."""
    def model_json_schema(cls):
        req = [k for k, (_, f) in cls.__arcaeon_fields__.items() if f.default is ...]
        return {"title": name, "type": "object",
                "properties": {k: {} for k in cls.__arcaeon_fields__}, "required": req}
    return type(name, (), {"__arcaeon_fields__": dict(fields),
                           "model_json_schema": classmethod(model_json_schema)})


@pytest.fixture()
def pydantic_mod(fake_module):
    """Real pydantic when installed (every framework that needs a model
    depends on it); a minimal fake otherwise, so the adapter tests always run."""
    try:
        import pydantic
        return pydantic
    except ImportError:
        return fake_module("pydantic", Field=_FakeFieldInfo, create_model=_fake_create_model)
