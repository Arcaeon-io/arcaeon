"""`arcaeon connect <client> --write`: backup first, merge only arcaeon (K020).

Every test writes into the fake home conftest.py points ARCAEON_CONNECT_HOME
at; HOME, USERPROFILE and APPDATA point at a separate temp folder, which
must never be created.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from arcaeon.connect import catalog as C
from arcaeon.connect import cli
from arcaeon.connect import write as W
from _connect import entry_for

TWO_SERVERS = (
    '{\n'
    '  "theme": "dark",\n'
    '  "mcpServers": {\n'
    '    "alpha": {\n'
    '      "command": "alpha-server",\n'
    '      "args": ["--port",   "9"]\n'
    '    },\n'
    '    "beta": {"url": "http://127.0.0.1:1/x", "env": {"K": "v\\u00e9"}}\n'
    '  },\n'
    '  "tail": [1, 2, 3]\n'
    '}\n')


def _run(capsys, *argv) -> tuple[int, str]:
    rc = cli.main(list(argv))
    return rc, capsys.readouterr().out


def _cursor() -> Path:
    path = C.config_path(entry_for("cursor"))
    assert path is not None, "cursor keeps a config file on every OS"
    return Path(path)


def _seed(text: str | bytes) -> Path:
    f = _cursor()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
    return f


def _snapshot(root: Path) -> dict:
    if not root.exists():
        return {}
    return {str(p.relative_to(root)): (hashlib.sha256(p.read_bytes()).hexdigest()
                                       if p.is_file() else "dir")
            for p in sorted(root.rglob("*"))}


def _span(text: str, name: str) -> str:
    """The raw text of server `name`'s value in TWO_SERVERS-shaped text."""
    doc = json.loads(text)
    start = text.index(f'"{name}": ') + len(f'"{name}": ')
    for end in range(start + 1, len(text) + 1):
        try:
            if json.loads(text[start:end]) == doc["mcpServers"][name]:
                return text[start:end]
        except ValueError:
            continue
    raise AssertionError(name)


def test_two_other_servers_stay_byte_equal(capsys):
    f = _seed(TWO_SERVERS)
    before = f.read_bytes()
    rc, out = _run(capsys, "cursor", "--write")
    assert rc == 0, out
    after = f.read_text(encoding="utf-8")
    for name in ("alpha", "beta"):
        assert _span(after, name) == _span(TWO_SERVERS, name), name
    doc = json.loads(after)
    assert doc["theme"] == "dark" and doc["tail"] == [1, 2, 3]
    assert set(doc["mcpServers"]) == {"alpha", "beta", "arcaeon"}
    assert doc["mcpServers"]["arcaeon"] == cli.server_entry(entry_for("cursor"))
    # everything before the splice point is the original, byte for byte
    cut = TWO_SERVERS.index("}}") + 2
    assert after[:cut] == TWO_SERVERS[:cut]
    baks = W.backups(f)
    assert len(baks) == 1 and baks[0].read_bytes() == before
    assert f"backup: {baks[0]}" in out
    assert "changed: mcpServers.arcaeon (added)" in out
    assert out.rstrip().splitlines()[-1] == "written"


def test_a_broken_json_file_is_untouched_and_exit_3(capsys):
    f = _seed(b'{"mcpServers": {"alpha": ')
    home = Path(os.environ[C.HOME_ENV])
    before = _snapshot(home)
    rc, out = _run(capsys, "cursor", "--write", "--json")
    d = json.loads(out)
    assert rc == 3 and d["exit"] == 3
    assert (d["verdict"], d["reason_word"], d["written"]) == ("COULD NOT LOOK", "unreadable",
                                                              False)
    assert _snapshot(home) == before and f.read_bytes() == b'{"mcpServers": {"alpha": '
    assert W.backups(f) == []


@pytest.mark.parametrize("text", ['[1, 2]', '{"mcpServers": ["x"]}', '{"mcpServers": 3}'])
def test_a_shape_it_cannot_merge_into_is_unreadable(capsys, text):
    f = _seed(text)
    rc, out = _run(capsys, "cursor", "--write")
    assert rc == 3 and "COULD NOT LOOK (unreadable)" in out and "nothing written" in out
    assert f.read_text(encoding="utf-8") == text and W.backups(f) == []


def test_bytes_that_are_not_utf8_are_unreadable(capsys):
    f = _seed(b'{"a": "\xff"}')
    assert _run(capsys, "cursor", "--write")[0] == 3
    assert f.read_bytes() == b'{"a": "\xff"}'


def test_a_missing_file_is_created_with_an_absent_marker(capsys):
    f = _cursor()
    assert not f.parent.exists()
    rc, out = _run(capsys, "cursor", "--write", "--json")
    d = json.loads(out)
    assert rc == 0 and d["written"] and d["backup_kind"] == "absent"
    assert json.loads(f.read_text(encoding="utf-8")) == cli.merge_json(entry_for("cursor"))
    marker = Path(d["backup"])
    assert marker.name.endswith(W.ABSENT) and marker.parent == f.parent
    assert str(f.parent) in json.loads(marker.read_text(encoding="utf-8"))["created_dirs"]


def test_an_old_arcaeon_entry_is_replaced_only(capsys):
    text = '{"mcpServers": {"arcaeon": {"command": "old"}, "z": {"command": "zz"}}}'
    f = _seed(text)
    rc, out = _run(capsys, "cursor", "--write")
    assert rc == 0 and "changed: mcpServers.arcaeon (replaced)" in out
    new = f.read_text(encoding="utf-8")
    assert new.endswith(', "z": {"command": "zz"}}}')
    assert json.loads(new)["mcpServers"]["arcaeon"] == cli.server_entry(entry_for("cursor"))


def test_the_same_entry_already_there_writes_nothing(capsys):
    f = _seed(json.dumps(cli.merge_json(entry_for("cursor"))))
    before = f.read_bytes()
    rc, out = _run(capsys, "cursor", "--write")
    assert rc == 0 and "already there" in out
    assert f.read_bytes() == before and W.backups(f) == []


def test_no_key_yet_adds_the_key(capsys):
    f = _seed('{\n  "other": 1\n}\n')
    rc, out = _run(capsys, "cursor", "--write")
    assert rc == 0 and "changed: mcpServers (added)" in out
    assert f.read_text(encoding="utf-8").startswith('{\n  "other": 1,\n  "mcpServers": {\n')


def test_crlf_and_a_bom_are_kept(capsys):
    raw = b'\xef\xbb\xbf{\r\n  "mcpServers": {\r\n    "a": {"command": "x"}\r\n  }\r\n}\r\n'
    f = _seed(raw)
    assert _run(capsys, "cursor", "--write")[0] == 0
    new = f.read_bytes()
    assert new.startswith(b'\xef\xbb\xbf{\r\n  "mcpServers": {\r\n    "a": {"command": "x"},\r\n')
    assert b"\n" not in new.replace(b"\r\n", b"")
    assert W.backups(f)[0].read_bytes() == raw


def test_an_empty_key_object_is_filled(capsys):
    f = _seed('{\n  "mcpServers": {}\n}\n')
    assert _run(capsys, "cursor", "--write")[0] == 0
    text = f.read_text(encoding="utf-8")
    assert text.startswith('{\n  "mcpServers": {\n    "arcaeon": {\n')
    assert json.loads(text)["mcpServers"]["arcaeon"]["args"]


def test_an_unconfirmed_path_is_refused_without_path(capsys, tmp_path):
    home = Path(os.environ[C.HOME_ENV])
    rc, out = _run(capsys, "vscode", "--write", "--json")
    d = json.loads(out)
    assert rc == 3 and d["reason_word"] == "path_unconfirmed" and not d["written"]
    assert not home.exists()
    target = tmp_path / "chosen" / "mcp.json"
    rc, out = _run(capsys, "vscode", "--write", "--path", str(target))
    assert rc == 0, out
    assert json.loads(target.read_text(encoding="utf-8"))["servers"]["arcaeon"]["type"] == "stdio"


def test_write_acts_on_this_machine_only(capsys):
    other = "linux" if C.current_os() == "windows" else "windows"
    assert cli.main(["cursor", "--write", "--os", other]) == 2
    assert not Path(os.environ[C.HOME_ENV]).exists()


def test_nothing_outside_the_fake_home_is_touched(capsys, _no_real_home):
    _seed(TWO_SERVERS)
    for name in C.names():
        cli.main([name, "--write"])
    capsys.readouterr()
    assert not _no_real_home.exists()


def test_two_writes_keep_two_backups_newest_last(capsys):
    f = _seed('{"mcpServers": {}}')
    assert _run(capsys, "cursor", "--write")[0] == 0
    f.write_bytes(b'{"mcpServers": {"arcaeon": {"command": "changed"}}}')
    assert _run(capsys, "cursor", "--write")[0] == 0
    baks = W.backups(f)
    assert [b.read_bytes() for b in baks] == [
        b'{"mcpServers": {}}', b'{"mcpServers": {"arcaeon": {"command": "changed"}}}']


# --- OA4: the file vanishes mid-write ------------------------------------------------

def _vanish_setup(tmp_path):
    d = tmp_path / "cfg"
    d.mkdir()
    f = d / "mcp.json"
    f.write_text(TWO_SERVERS, encoding="utf-8")
    other = d / "keep.txt"
    other.write_bytes(b"untouched")
    return d, f, other


def _assert_vanished(res, d, f, other):
    assert res["verdict"] == "COULD NOT LOOK" and res["exit"] == 3
    assert res["reason_word"] == "target_vanished" and res["written"] is False
    assert sorted(p.name for p in d.iterdir()) == ["keep.txt"]   # no backup, tmp or sidecar
    assert other.read_bytes() == b"untouched" and not f.exists()


def test_file_removed_between_the_read_and_the_replace_is_target_vanished(tmp_path,
                                                                         monkeypatch):
    d, f, other = _vanish_setup(tmp_path)
    real = os.replace

    def replace(src, dst):
        if Path(dst) == f:
            f.unlink()                   # another program removes the target
            raise FileNotFoundError(2, "No such file or directory", str(dst))
        return real(src, dst)
    monkeypatch.setattr(W.os, "replace", replace)
    res = W.write(f, "mcpServers", "arcaeon", {"command": "arcaeon"})
    _assert_vanished(res, d, f, other)


def test_file_removed_right_after_the_first_read_is_target_vanished(tmp_path, monkeypatch):
    d, f, other = _vanish_setup(tmp_path)
    real = W.merge_text

    def merge(*a, **k):
        out = real(*a, **k)
        f.unlink()
        return out
    monkeypatch.setattr(W, "merge_text", merge)
    res = W.write(f, "mcpServers", "arcaeon", {"command": "arcaeon"})
    _assert_vanished(res, d, f, other)
