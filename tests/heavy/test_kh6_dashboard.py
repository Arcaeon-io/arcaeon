"""KH6: the local dashboard slice, clicked through end to end.

One served root, seeded with real data: a ledger written by `log`, an empty
ledger (a COULD NOT LOOK on purpose), two evidence packs built with
build_pack (one whole, one with its window file taken away), two readings
ledgers for a compare, and a mandate file with a seam ledger holding two
gated sessions (one call the gate could not judge).

A headless client signs in the way `arcaeon open` does (a one-time code
minted with the token, spent once for the session cookie), then follows only
the links the shell renders, from the home page outward, and posts only the
forms the pages render, with the cookie and this server's own Origin. On
every page it asserts:

- the verdict words appear only as arcaeon.words renders them (word, tone
  class and sentence agree; COULD NOT LOOK is never inside a state-ok);
- COULD NOT LOOK is shown, never hidden (no hidden ancestor, no hiding rule in
  the CSS or the script), and it is on screen wherever the data holds one;
- no absolute path appears anywhere in the HTML (the served root shows as
  root-relative, and nothing outside it shows at all);
- nothing inline violates the CSP (no inline script or style, no event
  handler attributes, no javascript: or off-site URLs);
- a cross-origin post of each real form is refused (403) and runs nothing.

urllib and html.parser only; no browser. No network beyond 127.0.0.1; the one
server this test starts is stopped when it ends.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

import pytest

from arcaeon import journal, words
from arcaeon import verdict as V
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.readings_cli import submit
from arcaeon.record.adapter import mandate_gate, proxy
from arcaeon.record.adapter._ledger import open_ledger
from arcaeon.record.adapter.observer import SeamObserver
from arcaeon.serve import auth
from arcaeon.serve import dashboard as D
from arcaeon.serve import h_core
from serve import _pages as P

CNL = V.COULD_NOT_LOOK
CRITERION = "Does the claim say the delivery arrived on time?"
MANDATE = {"who": "purchasing-agent", "allowed_acts": ["search_*", "get_quote"],
           "forbidden_acts": ["refund", "delete_*"]}
REFUSAL_WORDS = {"Not checked", "Not compared", "Not read", "Not explained"}
HOSTILE_ORIGINS = ("http://evil.example", "null", None, "http://localhost:1")


# --- seeding -------------------------------------------------------------------
def _call(i, tool):
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                       "params": {"name": tool, "arguments": {}}}).encode()


def _gated_session(log, mandate, sid, tools, *, unparsed=False):
    obs = SeamObserver(log.append, server="stub", session=sid)
    watch = proxy._MandateWatch(mandate_gate.load(str(mandate)), obs, enforce=False)
    obs.session_begin()
    for i, tool in enumerate(tools):
        watch.observe(_call(i, tool))
    if unparsed:
        watch.record_unparsed("forwarded", "client stdin")
    obs.session_end(reason="eof", exit_code=0, **watch.session_end_fields())


def _readings(path, reader_id, provider, readings):
    for cid, word in readings:
        res = submit(path, reader_id=reader_id, provider=provider, claim_id=cid,
                     claim_text=f"claim text {cid}", reading=word, criterion_text=CRITERION)
        assert res["exit"] == 0, res


def _seed(base: Path) -> Path:
    root = base / "root"
    (root / "ledgers").mkdir(parents=True)
    (root / "reads").mkdir()
    main = root / "ledgers" / "main.jsonl"
    for i in range(4):
        res = h_core.log({"ledger": str(main),
                          "fields": {"agent": "buyer", "t": f"2026-09-27T10:0{i}:00Z", "n": i}})
        assert res["exit"] == 0, res
    (root / "ledgers" / "empty.jsonl").write_text("", encoding="utf-8")
    assert build_pack(main, root / "packs" / "good")["exit"] == 0
    assert build_pack(main, root / "packs" / "gone")["exit"] == 0
    # OA1: a listed file gone is BROKEN; the unlisted sidecar gone stays COULD NOT LOOK
    (root / "packs" / "gone" / "manifest.sha256").unlink()
    _readings(root / "reads" / "a.jsonl", "reader-alpha", "vendor-one",
              [("c1", "yes"), ("c2", "no"), ("c3", "yes"), ("c4", "no")])
    _readings(root / "reads" / "b.jsonl", "reader-beta", "vendor-two",
              [("c1", "yes"), ("c2", "yes"), ("c3", "yes"), ("c4", "yes")])
    m = root / "mandate.json"
    m.write_text(json.dumps(MANDATE), encoding="utf-8")
    seam = open_ledger(root / "seam.jsonl")
    _gated_session(seam, m, "session-one", ["search_web", "delete_everything"])
    _gated_session(seam, m, "session-two", ["search_web", "get_quote", "refund"],
                   unparsed=True)
    # Outside the served root: must never be listed, opened or named.
    (base / "outside.jsonl").write_bytes(main.read_bytes())
    (base / "outside.json").write_text(json.dumps(MANDATE), encoding="utf-8")
    return root


# --- a tiny browser: links, forms, cookie, Origin -----------------------------------
def _links(tree) -> list[str]:
    out = []
    for n in P.by_tag(tree, "a"):
        href = n.attrs.get("href") or ""
        if href.startswith("/") and not href.startswith("//"):
            out.append(href)
    return out


def _forms(tree) -> list[dict]:
    forms = []
    for f in P.by_tag(tree, "form"):
        fields, selects = {}, {}
        for n in f.walk():
            name = n.attrs.get("name")
            if not name:
                continue
            if n.tag == "input":
                fields[name] = n.attrs.get("value") or ""
            elif n.tag == "textarea":
                fields[name] = ""
            elif n.tag == "select":
                opts = [o.attrs.get("value", "") for o in P.by_tag(n, "option")]
                selects[name] = opts
                fields[name] = opts[0] if opts else ""
        forms.append({"method": (f.attrs.get("method") or "get").lower(),
                      "action": f.attrs.get("action") or "", "fields": fields,
                      "selects": selects})
    return forms


class Browser:
    def __init__(self, srv):
        self.srv, self.cookie, self.seen = srv, None, []

    def sign_in(self):
        """What `arcaeon open` does: mint with the token, spend the code once."""
        minted = P.mint(self.srv)
        assert minted.status == 200
        code = json.loads(minted.text)["code"]
        r = P.get(self.srv, "/?t=" + urllib.parse.quote(code))
        assert r.status == 303 and r.headers["Location"] == "/"
        self.cookie = r.headers["Set-Cookie"].split(";", 1)[0]
        assert "HttpOnly" in r.headers["Set-Cookie"]
        assert "SameSite=Strict" in r.headers["Set-Cookie"]
        again = P.get(self.srv, "/?t=" + urllib.parse.quote(code))
        assert again.status == 401                    # the code works once
        self.seen.append(("GET /?t (spent)", again))
        return r

    def get(self, path):
        r = P.get(self.srv, path, cookie=self.cookie)
        self.seen.append((f"GET {path}", r))
        return r

    def submit(self, form, choose: dict, *, origin="self"):
        """Post a rendered form; every chosen value must be one the page offers."""
        assert form["method"] == "post"
        fields = dict(form["fields"])
        for k, v in choose.items():
            assert k in fields, (k, form)
            if k in form["selects"]:
                assert v in form["selects"][k], (k, v, form["selects"][k])
            fields[k] = v
        r = P.post_form(self.srv, form["action"], fields, cookie=self.cookie, origin=origin)
        if origin == "self":
            self.seen.append((f"POST {form['action']} {choose}", r))
        return r


# --- the checks every page gets -------------------------------------------------
_DRIVE = re.compile(r"(?<![A-Za-z])[A-Za-z]:(?:\\\\|\\|/)")
_POSIX = re.compile(r"(?<![\w.:/])/(?:Users|home|tmp|var|private|root)/", re.I)


def _norm(s: str) -> str:
    return " ".join(s.split())


def _own_text(n) -> str:
    return " ".join(c for c in n.children if isinstance(c, str))


def _ancestors(n):
    p = n.parent
    while p is not None:
        yield p
        p = p.parent


def check_page(label, reply, base: Path, home: Path):
    html = reply.text
    tree = P.parse(html)
    assert reply.headers["Content-Security-Policy"] == D.CSP, label
    assert "unsafe-inline" not in D.CSP and "default-src 'self'" in D.CSP
    assert "The page could not finish" not in html, label

    # 1. verdict words only as arcaeon.words renders them
    for block in P.by_class(tree, "verdict"):
        wn = P.by_class(block, "verdict-word")
        if not wn:
            continue
        word = wn[0].text()
        if word in REFUSAL_WORDS:
            assert "state-unknown" in block.classes, (label, word)
            continue
        assert word in words.SENTENCES, (label, word)
        assert f"state-{words.tone(word)}" in block.classes, (label, word, block.classes)
        sent = P.by_class(block, "verdict-sentence")[0].text()
        assert sent == _norm(words.sentence(word)), (label, word, sent)
    for n in tree.walk():
        states = {c for c in n.classes if c.startswith("state-")}
        if not states:
            continue
        text = n.text()
        if "state-ok" in states:
            # Inside a green answer, COULD NOT LOOK and BROKEN may only be a
            # column name over a count of zero, never a finding.
            for d in [n, *n.walk()]:
                own = _own_text(d)
                if CNL in own or V.BROKEN in own or "could not" in own.lower():
                    assert d.tag == "th", (label, d.tag, own)
                if d.attrs.get("data-word") in (CNL, V.BROKEN):
                    assert d.text() == "0", (label, d.attrs["data-word"], d.text())
        word = n.attrs.get("data-word") or (text if text in words.SENTENCES else None)
        if word:
            assert states == {f"state-{words.tone(word)}"}, (label, word, states)

    # 2. COULD NOT LOOK shown, never hidden
    for n in tree.walk():
        if CNL not in _own_text(n):
            continue
        for a in [n, *_ancestors(n)]:
            if a.tag == "#root":
                break
            assert "hidden" not in a.attrs and a.attrs.get("aria-hidden") != "true", label
            assert "style" not in a.attrs, label
            assert a.tag not in ("details", "template", "noscript", "script", "style",
                                 "head"), (label, a.tag)

    # 3. no absolute path, least of all one outside the served root
    variants = set()
    for p in (base, home, Path.home()):
        s = str(p)
        variants |= {s, s.replace("\\", "/"), s.replace("\\", "\\\\"),
                     urllib.parse.quote(s), urllib.parse.quote(s.replace("\\", "/"))}
    for v in variants:
        assert v.lower() not in html.lower(), (label, "path shown")
    assert not _DRIVE.search(html), (label, _DRIVE.search(html).group(0))
    assert not _POSIX.search(html), (label, _POSIX.search(html).group(0))
    assert "outside.json" not in html, label
    assert "file:" not in html.lower(), label

    # 4. nothing inline the CSP would block, nothing from elsewhere
    for n in tree.walk():
        assert n.tag != "style", label
        assert "style" not in n.attrs, (label, n.tag)
        for k, v in n.attrs.items():
            assert not k.lower().startswith("on"), (label, n.tag, k)
            if k in ("href", "src", "action", "formaction", "srcset", "poster", "data"):
                v = (v or "").strip()
                assert v.startswith("/") and not v.startswith("//"), (label, k, v)
        if n.tag == "script":
            assert (n.attrs.get("src") or "").startswith("/static/"), label
            assert not _norm(n.text()), (label, "inline script")
        if n.tag == "meta":
            assert "http-equiv" not in n.attrs, label
    return tree


# --- the click-through ---------------------------------------------------------------
@pytest.fixture(scope="module")
def site(tmp_path_factory):
    base = tmp_path_factory.mktemp("kh6")
    home = base / "home"
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("ARCAEON_HOME", str(home))
        mp.delenv("ARCAEON_JOURNAL", raising=False)
        mp.delenv("ARCAEON_KEY", raising=False)
        root = _seed(base)
        out = {"base": base, "home": home, "root": root, "refused": [], "results": {}}
        with P.running(root) as srv:
            b = Browser(srv)
            out["unsigned"] = P.get(srv, "/status")
            out["signin"] = b.sign_in()

            # Follow the shell's own links, breadth first, from "/".
            queue, visited, assets = ["/"], {}, set()
            while queue:
                path = queue.pop(0)
                if path in visited:
                    continue
                r = b.get(path)
                assert r.status == 200, (path, r.status)
                tree = P.parse(r.text)
                visited[path] = tree
                for h in _links(tree):
                    if h not in visited:
                        queue.append(h)
                for n in tree.walk():
                    if n.tag in ("link", "script") and (n.attrs.get("href") or n.attrs.get("src")):
                        assets.add(n.attrs.get("href") or n.attrs.get("src"))
            out["visited"] = visited
            out["assets"] = {a: P.get(srv, a, cookie=b.cookie) for a in sorted(assets)}

            def form_on(path, action=None):
                fs = [f for f in _forms(visited[path]) if f["action"] == (action or path)]
                assert fs, path
                return fs

            R = out["results"]
            # Verify: every ledger the picker offers, then a pasted one.
            vf = form_on("/verify")[0]
            for opt in [o for o in vf["selects"]["ledger"] if o]:
                R[("verify", opt)] = b.submit(vf, {"ledger": opt})
            pasted = (root / "ledgers" / "main.jsonl").read_text(encoding="utf-8")
            R[("verify", "pasted")] = b.submit(vf, {"content": pasted.replace("\n", "\r\n")})
            # Packs: every pack's own button.
            for pf in form_on("/packs"):
                R[("packs", pf["fields"]["pack"])] = b.submit(pf, {})
            # Readings: a with b, and a with the empty ledger.
            rf = form_on("/readings")[0]
            R[("readings", "a-b")] = b.submit(rf, {"a": "reads/a.jsonl", "b": "reads/b.jsonl"})
            R[("readings", "a-empty")] = b.submit(
                rf, {"a": "reads/a.jsonl", "b": "ledgers/empty.jsonl"})
            # Mandate: the file with the seam ledger.
            mf = form_on("/mandate")[0]
            R[("mandate", "seam")] = b.submit(mf, {"mandate": "mandate.json",
                                                   "ledger": "seam.jsonl"})
            # Status again, now that the checks have been journaled.
            out["status_after"] = b.get("/status")

            # Cross-origin: each real form, each hostile Origin, runs nothing.
            before = len(journal.read())
            for f, choose in ((vf, {"ledger": "ledgers/main.jsonl"}),
                              (form_on("/packs")[0], {}),
                              (rf, {"a": "reads/a.jsonl", "b": "reads/b.jsonl"}),
                              (mf, {"mandate": "mandate.json", "ledger": "seam.jsonl"})):
                for origin in HOSTILE_ORIGINS:
                    out["refused"].append((f["action"], origin, b.submit(f, choose, origin=origin)))
            out["journal_delta"] = len(journal.read()) - before
            out["seen"] = b.seen
        yield out


def _verdict(reply):
    tree = P.parse(reply.text)
    blocks = [x for x in P.by_class(tree, "verdict") if P.by_class(x, "verdict-word")]
    assert blocks, reply.text
    return tree, blocks[0], P.by_class(blocks[0], "verdict-word")[0].text()


def test_the_shell_links_reach_every_page(site):
    assert set(site["visited"]) == set(D.PAGES)
    for path, tree in site["visited"].items():
        current = [n.attrs["href"] for n in P.by_tag(tree, "a")
                   if n.attrs.get("aria-current") == "page"]
        assert current == [path]
    assert set(site["assets"]) == {"/static/placeholder.css", "/static/app.js"}
    assert all(r.status == 200 for r in site["assets"].values())


def test_sign_in_is_one_time_and_pages_need_it(site):
    assert site["unsigned"].status == 401
    assert "arcaeon open" in site["unsigned"].text
    assert site["signin"].status == 303


def test_every_page_and_answer_passes_the_four_checks(site):
    assert len(site["seen"]) >= 20
    for label, reply in site["seen"]:
        assert reply.headers.get_content_type() == "text/html", label
        check_page(label, reply, site["base"], site["home"])
    for label, reply in (("unsigned", site["unsigned"]), ("signin", site["signin"])):
        check_page(label, reply, site["base"], site["home"])


def test_css_and_script_never_hide_anything(site):
    css = site["assets"]["/static/placeholder.css"].text
    js = site["assets"]["/static/app.js"].text
    assert "TODO(design-system)" in css
    assert not re.search(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?!\.)",
                         css, re.I)
    assert not re.search(r"\.hidden|\.remove\(|removeChild|innerHTML|style\.|fetch\(|"
                         r"XMLHttpRequest", js)


def test_verify_answers(site):
    R = site["results"]
    assert {k[1] for k in R if k[0] == "verify"} >= {"ledgers/main.jsonl",
                                                    "ledgers/empty.jsonl", "pasted"}
    assert not any("outside" in k[1] for k in R if k[0] == "verify")
    for key in (("verify", "ledgers/main.jsonl"), ("verify", "pasted")):
        _, block, word = _verdict(R[key])
        assert R[key].status == 200 and word == V.VERIFIED and "state-ok" in block.classes
    _, block, word = _verdict(R[("verify", "ledgers/empty.jsonl")])
    assert word == CNL and "state-unknown" in block.classes and "state-ok" not in block.classes
    assert "empty" in block.text()


def test_packs_answers(site):
    R = site["results"]
    assert {k[1] for k in R if k[0] == "packs"} == {"packs/good", "packs/gone"}
    _, block, word = _verdict(R[("packs", "packs/good")])
    assert word == V.VERIFIED and "state-ok" in block.classes
    _, block, word = _verdict(R[("packs", "packs/gone")])
    assert word == CNL and "state-unknown" in block.classes
    cells = {n.attrs["data-word"]: int(n.text()) for n in P.by_class(block, "count")}
    assert list(cells) == [V.VERIFIED, V.BROKEN, CNL] and cells[CNL] > 0
    rows = [r for r in P.by_tag(block, "td") if r.text() == CNL]
    assert rows and all("state-unknown" in r.classes for r in rows)


def test_readings_answers(site):
    R = site["results"]
    tree, block, word = _verdict(R[("readings", "a-b")])
    assert word == V.COMPARED and "state-ok" in block.classes
    counts = {n.attrs["data-count"]: int(n.text()) for n in P.by_class(block, "count")}
    assert counts == {"disagreed": 2, "read": 4}
    assert P.by_class(block, "not-yet-informative")
    readers = {P.by_class(x, "reader-a")[0].text() + "|" + P.by_class(x, "reader-b")[0].text()
               for x in P.by_class(tree, "disagreed") if x.tag == "tr"}
    assert readers == {"reader-alpha|reader-beta"}
    _, block, word = _verdict(R[("readings", "a-empty")])
    assert word != V.COMPARED and "state-ok" not in block.classes


def test_mandate_answers(site):
    tree, block, word = _verdict(site["results"][("mandate", "seam")])
    assert word == V.VERIFIED
    assert P.by_tag(P.by_class(tree, "mandate-sentences")[0], "li")
    assert "session-two" in P.by_class(tree, "session")[0].text()
    outside = [r for t in P.by_class(tree, "outside-rows") for r in P.by_tag(t, "tr")[1:]]
    assert outside and all("state-bad" in r.classes for r in outside)
    assert any("refund" in r.text() for r in outside)
    cnl = [r for t in P.by_class(tree, "cnl-rows") for r in P.by_tag(t, "tr")[1:]]
    assert cnl and all("state-unknown" in r.classes for r in cnl)
    last = P.by_class(site["visited"]["/mandate"], "last-session")[0]
    assert "1 COULD NOT LOOK" in last.text() and "state-ok" not in last.classes


def test_status_shows_the_open_could_not_looks(site):
    r = site["status_after"]
    tree = P.parse(r.text)
    head = P.by_class(tree, "open-count")[0]
    n = int(head.text().rsplit(":", 1)[1])
    assert n >= 2 and "state-unknown" in head.classes        # empty ledger, gone pack
    rows = [x for t in P.by_class(tree, "open-cnl") for x in P.by_tag(t, "tr")[1:]]
    assert len(rows) == n and all("state-unknown" in x.classes for x in rows)
    headline = P.by_class(tree, "headline")[0].text()
    assert "could not be read" in headline
    assert "state-ok" not in P.by_class(tree, "verdict")[0].classes
    assert "Every one was checked to the end and held." not in headline


def test_cross_origin_posts_are_refused_and_run_nothing(site):
    assert len(site["refused"]) == 4 * len(HOSTILE_ORIGINS)
    for action, origin, r in site["refused"]:
        assert r.status == 403, (action, origin, r.status)
        tree = P.parse(r.text)
        assert not [x for x in P.by_class(tree, "verdict") if P.by_class(x, "verdict-word")]
        assert _norm(auth.ORIGIN_REFUSED) in _norm(tree.text())
        check_page(f"refused {action} {origin}", r, site["base"], site["home"])
    assert site["journal_delta"] == 0
