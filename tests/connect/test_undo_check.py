"""`connect --undo` and `connect --check` (K021).

The golden round trip: snapshot the fake home, --check, --write, --check,
--undo, and the fake home is byte-identical to the snapshot, backups and
created directories included.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from arcaeon.connect import catalog as C
from arcaeon.connect import cli
from arcaeon.connect import write as W

OTHERS = '{\n  "mcpServers": {\n    "alpha": {"command": "a"},\n    "beta": {"command": "b"}\n  }\n}\n'


def _run(capsys, *argv) -> tuple[int, str]:
    rc = cli.main(list(argv))
    return rc, capsys.readouterr().out


def _home() -> Path:
    return Path(os.environ[C.HOME_ENV])


def _snapshot(root: Path) -> dict:
    if not root.exists():
        return {}
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest()
                                       if p.is_file() else "dir")
            for p in sorted(root.rglob("*"))}


def _seed(entry_name: str, text: str) -> Path:
    f = Path(C.config_path(C.get(entry_name)))
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(text.encode("utf-8"))
    return f


WRITABLE = [e.name for e in C.CATALOG if e.writes_file and C.confirmed_for(e)]


@pytest.mark.parametrize("name", WRITABLE)
@pytest.mark.parametrize("seeded", [True, False], ids=["existing", "absent"])
def test_write_then_undo_is_byte_identical(capsys, name, seeded):
    home = _home()
    home.mkdir(parents=True, exist_ok=True)
    (home / "keep.txt").write_bytes(b"not arcaeon's\r\n")
    if seeded:
        e = C.get(name)
        _seed(name, OTHERS.replace("mcpServers", e.key))
    before = _snapshot(home)
    assert _run(capsys, name, "--check")[0] in (0, 1)
    assert _snapshot(home) == before                     # check reads only
    rc, out = _run(capsys, name, "--write")
    assert rc == 0 and "written" in out
    assert _snapshot(home) != before
    rc, out = _run(capsys, name, "--undo")
    assert rc == 0, out
    assert _snapshot(home) == before


def test_vscode_round_trip_with_path(capsys, tmp_path):
    f = tmp_path / "chosen" / "mcp.json"
    f.parent.mkdir()
    f.write_bytes(b'{"servers": {"x": {"type": "stdio", "command": "x"}}}')
    before = _snapshot(tmp_path / "chosen")
    assert _run(capsys, "vscode", "--write", "--path", str(f))[0] == 0
    assert _run(capsys, "vscode", "--undo", "--path", str(f))[0] == 0
    assert _snapshot(tmp_path / "chosen") == before


def test_two_writes_two_undos_newest_first(capsys):
    f = _seed("cursor", OTHERS)
    assert _run(capsys, "cursor", "--write")[0] == 0
    mid = f.read_bytes().replace(b'"b"', b'"b2"')
    f.write_bytes(mid)
    assert _run(capsys, "cursor", "--write")[0] == 0      # entry the same: nothing
    f.write_bytes(mid.replace(b'"args"', b'"argz"'))
    assert _run(capsys, "cursor", "--write")[0] == 0
    assert len(W.backups(f)) == 2
    rc, out = _run(capsys, "cursor", "--undo")
    assert rc == 0 and "backups left: 1" in out
    assert f.read_bytes() == mid.replace(b'"args"', b'"argz"')
    assert _run(capsys, "cursor", "--undo")[0] == 0
    assert f.read_bytes() == OTHERS.encode("utf-8") and W.backups(f) == []


def test_undo_with_no_backup_is_3_and_changes_nothing(capsys):
    f = _seed("cursor", OTHERS)
    rc, out = _run(capsys, "cursor", "--undo", "--json")
    d = json.loads(out)
    assert rc == 3 and d["reason_word"] == "no_backup"
    assert f.read_bytes() == OTHERS.encode("utf-8")


def test_check_present_absent_stale(capsys, monkeypatch):
    rc, out = _run(capsys, "cursor", "--check")
    assert rc == 1 and "state: absent  (the file is not there)" in out
    f = _seed("cursor", OTHERS)
    rc, out = _run(capsys, "cursor", "--check", "--json")
    assert (rc, json.loads(out)["state"]) == (1, "absent")
    real_which = shutil.which
    monkeypatch.setattr(shutil, "which", lambda c, *a, **k: "/fake/bin/" + c)
    assert _run(capsys, "cursor", "--write")[0] == 0
    rc, out = _run(capsys, "cursor", "--check", "--json")
    d = json.loads(out)
    assert (rc, d["state"], d["matches"]) == (0, "present", True)
    monkeypatch.setattr(shutil, "which", lambda c, *a, **k: None)
    rc, out = _run(capsys, "cursor", "--check")
    assert rc == 1 and "state: stale" in out and "does not resolve here" in out
    monkeypatch.setattr(shutil, "which", real_which)
    f.write_bytes(b'{"mcpServers": {"arcaeon": {"command": "' +
                  str(f).replace("\\", "\\\\").encode() + b'"}}}')
    rc, out = _run(capsys, "cursor", "--check")            # an absolute path that exists
    assert rc == 0 and "state: present" in out


def test_check_on_a_broken_file_is_could_not_look(capsys):
    f = _seed("cursor", "{nope")
    before = _snapshot(_home())
    rc, out = _run(capsys, "cursor", "--check", "--json")
    d = json.loads(out)
    assert rc == 3 and (d["verdict"], d["reason_word"]) == ("COULD NOT LOOK", "unreadable")
    assert _snapshot(_home()) == before and f.read_bytes() == b"{nope"


def test_check_says_when_the_path_is_unconfirmed(capsys):
    rc, out = _run(capsys, "vscode", "--check")
    assert rc == 1 and "confirmed: NO" in out


def test_actions_do_not_combine(capsys):
    assert cli.main(["cursor", "--write", "--undo"]) == 2
    assert cli.main(["cursor", "--check", "--os",
                     "linux" if C.current_os() == "windows" else "windows"]) == 2


def test_doctor_asks_connect_check(monkeypatch):
    """doctor's client line is connect.write.check, not a second reader."""
    from arcaeon import doctor
    seen = []

    def fake(path, key, name, value=None):
        seen.append((path, key, name))
        return {"file": path, "exists": True, "state": "stale", "command": "gone",
                "exit": 1}

    monkeypatch.setattr(W, "check", fake)
    c = doctor.check_client(C.get("cursor"))
    assert seen == [(C.config_path(C.get("cursor")), "mcpServers", "arcaeon")]
    assert c["state"] == "stale" and "'gone'" in c["detail"]
