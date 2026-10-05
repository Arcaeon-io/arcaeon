# SPDX-License-Identifier: MIT
"""L3-06: account-as-ID end to end, over real localhost HTTP.

The reference server (`python -m arcaeon.prove.account_server serve`) runs as a
subprocess on an ephemeral 127.0.0.1 port. The owner issues an agent key over
HTTP, the agent's own exchange.binding row is the possession proof, the
public binding statement is fetched over HTTP into the file `exchange pair
--accounts` reads, the pair reads VERIFIED; the owner revokes over HTTP, the
statement is fetched again, a reaction the key signs after the revoke reads
BROKEN; the register page is built from the same server's register rows and
shows the revoked key. No mock of the HTTP layer. Every key is a throwaway
seed made in tmp_path; nothing leaves loopback."""
from __future__ import annotations

import base64
import json
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon import cli  # noqa: E402
from arcaeon import verdict as V  # noqa: E402
from arcaeon.prove import exchange_log as X  # noqa: E402
from arcaeon.prove import register as G  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OWNER = "acct:owner-a@arcaeon.io"
ACCT = "acct:bot1.owner-a@arcaeon.io"
MOD = [sys.executable, "-m", "arcaeon.prove.account_server"]


def _party(tmp: Path, name: str):
    from arcaeon.prove.vet import receipts as R
    seed = secrets.token_bytes(32)
    key = tmp / f"{name}.key"
    key.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return key, tmp / f"{name}.jsonl", R.did_key(R.public_key_from_seed(seed))


def _call(url, method="GET", body=None, token=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def _run(args):
    return subprocess.run(MOD + args, capture_output=True, text=True, timeout=60)


def _ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _pair(capsys, la, lb, accounts, key):
    capsys.readouterr()
    rc = cli.main(["exchange", "pair", str(la), str(lb), "--json", "--accounts", str(accounts),
                   "--account-key", key])
    return rc, json.loads(capsys.readouterr().out)


@pytest.fixture
def server(tmp_path):
    owner_tok, op_tok = secrets.token_hex(16), secrets.token_hex(16)
    auth = tmp_path / "auth.json"
    auth.write_text(json.dumps({"owners": {owner_tok: OWNER}, "register_operator": op_tok}),
                    encoding="utf-8")
    proc = subprocess.Popen(MOD + ["serve", "--port", "0", "--auth", str(auth)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        assert line, proc.stderr.read()
        info = json.loads(line)
        assert info["url"].startswith("http://127.0.0.1:")
        yield {**info, "owner": owner_tok, "operator": op_tok}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc.stdout.close()
        proc.stderr.close()


def test_account_id_end_to_end_over_real_http(server, tmp_path, capsys):
    url, bkey, rkey = server["url"], server["binding_key"], server["register_key"]
    ka, la, da = _party(tmp_path, "a")
    kb, lb, db = _party(tmp_path, "b")
    deliverable = tmp_path / "deliverable.csv"
    deliverable.write_bytes(b"id,grade\n1,A\n")

    # 1. the agent makes its own possession proof: its exchange.binding row
    proof = X.bind(la, key_file=ka, account=ACCT)["row"]
    assert _call(f"{url}/v1/agents", "POST", {"agent": "bot1", "proof": proof})[0] == 401
    st, body = _call(f"{url}/v1/agents", "POST", {"agent": "bot1", "proof": proof},
                     token=server["owner"])
    assert st == 201, body
    issued = body["binding"]
    assert issued["event"] == "issue" and issued["key"] == da and issued["signer"] == bkey
    assert issued["owner"] == OWNER and issued["agent_proof"] == proof
    t_issue = _ts(issued["at"])
    st, body = _call(f"{url}/v1/register/add", "POST",
                     {"member": OWNER, "what": "key", "value": da}, token=server["operator"])
    assert st == 201, body

    # 2. one exchange, both sides react
    X.react(la, key_file=ka, exchange_id="ex-1", counterparty=db, file=deliverable,
            reaction=V.VERIFIED, at=t_issue)
    X.react(lb, key_file=kb, exchange_id="ex-1", counterparty=ACCT, file=deliverable,
            reaction=V.VERIFIED, at=t_issue)

    # 3. fetch the public statement over HTTP into the --accounts file; pair
    acc1 = tmp_path / "accounts-1.json"
    r = _run(["fetch", url, "--did", da, "--out", str(acc1)])
    assert r.returncode == 0, r.stderr
    doc = json.loads(acc1.read_text(encoding="utf-8"))
    assert [s["did"] for s in doc["statements"]] == [da] and "fetched_at" in doc
    rc, p = _pair(capsys, la, lb, acc1, bkey)
    assert rc == V.EXIT_GOOD and p["verdict"] == V.VERIFIED, p["reason"]
    assert p["counts"]["clean"] == 1
    (svc,) = p["account_service"]["bindings"]
    assert svc["verdict"] == V.VERIFIED and svc["owner"] == OWNER

    # 4. the owner revokes over HTTP (a later second than the issue)
    while datetime.now(timezone.utc).replace(microsecond=0) <= t_issue:
        time.sleep(0.05)
    acct_path = urllib.parse.quote(ACCT, safe="")
    st, body = _call(f"{url}/v1/agents/{acct_path}/revoke", "POST", {"reason": "key lost"},
                     token=server["owner"])
    assert st == 200, body
    t_rev = body["binding"]["at"]
    st, body = _call(f"{url}/v1/register/revoke", "POST",
                     {"member": OWNER, "what": "key", "digest": G.thing_digest("key", da),
                      "reason": "key_compromise", "compromised_since": t_rev},
                     token=server["operator"])
    assert st == 201, body
    acc2 = tmp_path / "accounts-2.json"
    r = _run(["fetch", url, "--did", da, "--out", str(acc2)])
    assert r.returncode == 0, r.stderr
    assert [x["event"] for x in json.loads(acc2.read_text("utf-8"))["statements"][0]["rows"]] \
        == ["issue", "revoke"]

    # 5a. the same logs (every row before the revoke): VERIFIED, revocation shown
    rc, p = _pair(capsys, la, lb, acc2, bkey)
    assert rc == V.EXIT_GOOD and p["verdict"] == V.VERIFIED, p["reason"]
    assert "revoked later" in p["account_service"]["bindings"][0]["reason"]

    # 5b. the key goes on signing after the revoke: BROKEN with the fresh fetch
    la2, lb2 = tmp_path / "a2.jsonl", tmp_path / "b2.jsonl"
    shutil.copyfile(la, la2)
    shutil.copyfile(lb, lb2)
    X.react(la2, key_file=ka, exchange_id="ex-2", counterparty=db, file=deliverable,
            reaction=V.VERIFIED, at=_ts(t_rev))
    X.react(lb2, key_file=kb, exchange_id="ex-2", counterparty=ACCT, file=deliverable,
            reaction=V.VERIFIED, at=_ts(t_rev))
    rc, p = _pair(capsys, la2, lb2, acc2, bkey)
    assert rc == V.EXIT_BAD and p["verdict"] == V.BROKEN
    assert "revoked" in p["reason"] and "ex-2" in p["reason"]
    # ...while the stale first fetch does not see the revoke (as fresh as its fetch)
    rc, p = _pair(capsys, la2, lb2, acc1, bkey)
    assert p["verdict"] == V.VERIFIED and "as of" in p["account_service"]["reason"]

    # 6. the register page, from the same server's register rows
    reg = tmp_path / "register.jsonl"
    r = _run(["fetch-register", url, "--out", str(reg)])
    assert r.returncode == 0, r.stderr
    page = tmp_path / "page.html"
    capsys.readouterr()
    assert cli.main(["register", "page", str(reg), "--operator-key", rkey,
                     "--out", str(page)]) == V.EXIT_GOOD
    html = page.read_text(encoding="utf-8")
    assert "register VERIFIED" in html
    assert da in html
    assert f"REVOKED at {t_rev} (key_compromise), compromised since {t_rev}" in html
    rev = html.split("<h2>Revocations</h2>", 1)[1]
    assert "key_compromise" in rev and da in rev and "none in this register" not in rev


def test_the_doc_says_how_to_run_it_end_to_end():
    doc = (ROOT / "docs" / "ACCOUNT_ID_API.md").read_text(encoding="utf-8")
    assert "## Run it end to end" in doc
    sec = doc.split("## Run it end to end", 1)[1].split("\n## ", 1)[0]
    for w in ("python -m arcaeon.prove.account_server serve", "--port 0", "--auth",
              "/v1/agents", "/revoke", "account_server fetch", "--accounts",
              "--account-key", "arcaeon exchange pair", "fetch-register",
              "arcaeon register page", "tests/test_account_server_e2e.py"):
        assert w in sec, w
