"""Shared by the dashboard page tests (lane H): a loopback server the test
starts and stops, urllib with no proxy and no redirect-following, and a small
html.parser tree. No browser, no network beyond 127.0.0.1."""
from __future__ import annotations

import contextlib
import io
import threading
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

from arcaeon.serve import dashboard as D
from arcaeon.serve import server as S

TOKEN = "test-token-for-the-dashboard"

VOID = {"meta", "link", "br", "hr", "img", "input", "area", "base", "col", "embed",
        "source", "track", "wbr"}


@contextlib.contextmanager
def running(root, *, token=TOKEN):
    """A dashboard-mounted server on 127.0.0.1, port 0, fenced to `root`."""
    srv = D.make_dashboard_server(port=0, token=token, root=root)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(srv,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    try:
        yield srv
    finally:
        srv.shutdown()
        t.join(10)
        assert not t.is_alive()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class Reply:
    def __init__(self, status, headers, body: bytes):
        self.status, self.headers, self.body = status, headers, body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")


def request(srv, path, *, data: bytes | None = None, headers=None, method=None) -> Reply:
    req = urllib.request.Request(srv.url + path, data=data, headers=dict(headers or {}),
                                 method=method)
    try:
        with _OPENER.open(req, timeout=30) as r:
            return Reply(r.status, r.headers, r.read())
    except urllib.error.HTTPError as e:
        with e:
            return Reply(e.code, e.headers, e.read())


def get(srv, path, *, cookie=None, headers=None) -> Reply:
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = cookie
    return request(srv, path, headers=h)


def post_form(srv, path, fields: dict, *, cookie=None, origin="self", headers=None) -> Reply:
    """A browser's form post. `origin` "self" sends the server's own Origin,
    as a browser posting from the page does (K108); None sends none."""
    h = {"Content-Type": "application/x-www-form-urlencoded"}
    if origin == "self":
        h["Origin"] = srv.url
    elif origin is not None:
        h["Origin"] = origin
    if cookie:
        h["Cookie"] = cookie
    h.update(headers or {})
    return request(srv, path, data=urllib.parse.urlencode(fields).encode("utf-8"),
                   headers=h, method="POST")


def mint(srv, token=TOKEN) -> Reply:
    return request(srv, D.CODE_PATH, data=b"", method="POST",
                   headers={"Authorization": f"Bearer {token}"})


def sign_in(srv) -> str:
    """Cookie header value for a fresh browser session."""
    import json
    code = json.loads(mint(srv).text)["code"]
    r = get(srv, "/?t=" + urllib.parse.quote(code))
    assert r.status == 303, r.status
    return r.headers["Set-Cookie"].split(";", 1)[0]


class Node:
    def __init__(self, tag, attrs, parent=None):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children: list = []

    @property
    def classes(self) -> set[str]:
        return set((self.attrs.get("class") or "").split())

    def text(self) -> str:
        out = []
        for c in self.children:
            out.append(c if isinstance(c, str) else c.text())
        return " ".join(" ".join(out).split())

    def walk(self):
        for c in self.children:
            if isinstance(c, Node):
                yield c
                yield from c.walk()


class _Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", [])
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        n = Node(tag, attrs, self.cur)
        self.cur.children.append(n)
        if tag not in VOID:
            self.cur = n

    def handle_endtag(self, tag):
        n = self.cur
        while n is not self.root and n.tag != tag:
            n = n.parent
        if n is not self.root:
            self.cur = n.parent

    def handle_data(self, data):
        self.cur.children.append(data)


def parse(html: str) -> Node:
    p = _Tree()
    p.feed(html)
    p.close()
    return p.root


def by_class(root: Node, cls: str) -> list[Node]:
    return [n for n in root.walk() if cls in n.classes]


def by_tag(root: Node, tag: str) -> list[Node]:
    return [n for n in root.walk() if n.tag == tag]
