"""mcp_vet check tests — each failure class gets a planted red AND a clean
negative, so the checker is proven to fire on the bad shape and stay silent on
the good one before it ever judges real code."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arcaeon.prove.vet.checks import scan_source

def _kinds(src):
    return sorted({f.check for f in scan_source(src, "t.py")})

def test_unsafe_exec_fires():
    for bad in ("eval(user_in)", "exec(code)", "import os\nos.system(cmd)",
                "import subprocess\nsubprocess.run(cmd, shell=True)"):
        assert "unsafe-exec" in _kinds(bad), bad

def test_unsafe_exec_silent_on_safe():
    safe = "import subprocess\nsubprocess.run(['ls', '-l'])  # no shell\nx = evaluate(y)"
    assert "unsafe-exec" not in _kinds(safe), _kinds(safe)

def test_shell_via_list_form_fires():
    # sh -c / bash -c list form: shell injection with shell=False
    for bad in ("import subprocess\nsubprocess.Popen(['sh', '-c', cmd])",
                "import subprocess\nsubprocess.run(['/bin/bash', '-c', user])",
                "import subprocess\nsubprocess.call(['cmd', '/c', x])"):
        assert "unsafe-exec" in _kinds(bad), bad

def test_shell_list_form_silent_on_safe_argv():
    # a normal argv list (no shell binary + -c) must NOT fire
    safe = "import subprocess\nsubprocess.run(['git', 'status', '-s'])"
    assert "unsafe-exec" not in _kinds(safe), _kinds(safe)


def test_ssrf_tainted_is_high():
    src = ('from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n'
           '@mcp.tool()\ndef fetch(url):\n    import urllib.request\n'
           '    return urllib.request.urlopen(url).read()\n')
    fs = [f for f in scan_source(src, "t.py") if f.check == "ssrf"]
    assert fs and fs[0].severity == "high", fs

def test_ssrf_not_tainted_is_medium_and_no_net_outside_handler():
    # net call OUTSIDE any tool handler must not fire
    src = ('import urllib.request\nurllib.request.urlopen("https://fixed.example")\n')
    assert "ssrf" not in _kinds(src), _kinds(src)

_H = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n@mcp.tool()\n'


def _ssrf(src):
    return [f for f in scan_source(src, "t.py") if f.check == "ssrf"]


def test_ssrf_mapping_lookup_named_get_is_not_a_network_call():
    """The `_NET_CALLS` hole, closed 2026-09-05 on the verbatim mcp-atlassian
    handler: `project.get("key")` on a result dict and the git dispatcher's
    `arguments.get("repo_path")` are lookups, not requests. Must-miss."""
    for body in ('    for project in projects:\n        project["key"] = project.get("key").upper()\n',
                 '    path = arguments.get("repo_path")\n',
                 '    x = opts.get("mode", "fast")\n'):
        src = _H + "def t(projects, arguments, opts):\n" + body + "    return 1\n"
        assert not _ssrf(src), src


def test_ssrf_real_requests_still_fire_through_the_mapping_rule():
    """Must-hits the new rule must not eat: a name argument (tainted or not),
    a URL literal, a base-URL client path, and a string key with an HTTP-only
    keyword argument."""
    cases = {
        "tainted name": ('def t(url):\n    import requests\n    return requests.get(url)\n', "high"),
        "url literal": ('def t():\n    import requests\n    return requests.get("https://x.example/a")\n', "medium"),
        "client path": ('def t(client):\n    return client.get("/items")\n', "medium"),
        "http kwarg": ('def t(s, h):\n    return s.get("items", headers=h)\n', "medium"),
    }
    for name, (body, sev) in cases.items():
        fs = _ssrf(_H + body)
        assert fs, f"{name}: must fire"
        assert fs[0].severity == sev, (name, fs[0])


def test_zero_auth_fires_on_network_transport():
    src = ('from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n'
           'mcp.run(transport="sse")\n')
    assert "zero-auth" in _kinds(src), _kinds(src)

def test_zero_auth_silent_on_stdio():
    src = ('from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n'
           'mcp.run(transport="stdio")\n')
    assert "zero-auth" not in _kinds(src), _kinds(src)

def test_zero_auth_silent_when_auth_present():
    src = ('from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n'
           'API_KEY = "..."  # auth token check happens in middleware\n'
           'mcp.run(transport="sse")\n')
    assert "zero-auth" not in _kinds(src), _kinds(src)

def test_unreceipted_allow_fires_on_bare_pass_receipted_block():
    # toy server: a gate whose refusal is receipted and whose grant is bare
    src = (
        'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n\n'
        'def _gate(user, resource):\n'
        '    if not user.member_of(resource):\n'
        '        return {"allowed": False, "receipt": _hash(user, resource)}\n'
        '    return {"allowed": True}\n\n'
        '@mcp.tool()\ndef vet(user, resource):\n    return _gate(user, resource)\n'
    )
    fs = [f for f in scan_source(src, "t.py") if f.check == "unreceipted-allow"]
    assert fs, "bare pass next to a receipted block must fire"
    assert fs[0].severity == "high", fs
    assert fs[0].line == 7, fs  # the bare `{"allowed": True}` return

def test_unreceipted_allow_silent_when_both_paths_receipted():
    # control: minimally different -- the pass path also carries a receipt
    src = (
        'def _gate(user, resource):\n'
        '    if not user.member_of(resource):\n'
        '        return {"allowed": False, "receipt": _hash(user, resource)}\n'
        '    return {"allowed": True, "receipt": _hash(user, resource)}\n'
    )
    assert "unreceipted-allow" not in _kinds(src), _kinds(src)

def test_unreceipted_allow_silent_on_single_outcome_function():
    # only one verdict branch present -- nothing to compare, must stay quiet
    src = 'def _gate(user):\n    return {"allowed": True}\n'
    assert "unreceipted-allow" not in _kinds(src), _kinds(src)

def test_unreceipted_allow_silent_when_bare_verdict_field_names_generic():
    # deliberately-tight field list: "status"/"ok"/"result" are not verdict
    # fields (too generic, reused for unrelated success/failure everywhere)
    src = (
        'def handle(x):\n'
        '    if x < 0:\n'
        '        return {"status": "failed", "receipt": _hash(x)}\n'
        '    return {"status": "ok"}\n'
    )
    assert "unreceipted-allow" not in _kinds(src), _kinds(src)

def test_blind_spots_closed_2026_08_30():
    """The three named blind spots from v0.0.3, each now caught + a clean negative."""
    dyn = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n@mcp.tool()\ndef f(e):\n    return __import__('os').system(e)"
    assert "unsafe-exec" in _kinds(dyn), "dynamic-import evasion must be caught"
    alias = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n@mcp.tool()\ndef f(url):\n    import urllib.request\n    p=url\n    return urllib.request.urlopen(p).read()"
    assert "ssrf" in _kinds(alias), "aliased taint must be caught"
    trav = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n@mcp.tool()\ndef f(path):\n    return open(path).read()"
    assert "path-traversal" in _kinds(trav), "path traversal must be caught"
    # negatives: constant path + non-__import__ attribute must stay silent
    const = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n@mcp.tool()\ndef f(x):\n    return open('/etc/fixed.conf').read()"
    assert "path-traversal" not in _kinds(const), "constant path must not fire"
    ok = "import os.path\nos.path.join('a','b')"  # os.path.join is not an exec sink
    assert "unsafe-exec" not in _kinds(ok), "os.path.join must not fire"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}"); passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)


def test_import_form_exec_evasions_2026_09_01():
    """The 4th blind spot: unsafe-exec was name-shape matching, so ordinary
    import forms of the SAME sinks walked past. Each must now be caught."""
    hdr = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n"
    cases = [
        hdr + "from os import system\n@mcp.tool()\ndef f(c):\n    return system(c)",
        hdr + "import os as o\n@mcp.tool()\ndef f(c):\n    return o.system(c)",
        hdr + "from os import popen\n@mcp.tool()\ndef f(c):\n    return popen(c).read()",
        hdr + "import builtins\n@mcp.tool()\ndef f(c):\n    return builtins.eval(c)",
        hdr + "from os import system as run_it\n@mcp.tool()\ndef f(c):\n    return run_it(c)",
        hdr + "import importlib\n@mcp.tool()\ndef f(c):\n    return importlib.import_module('os').system(c)",
    ]
    for src in cases:
        assert "unsafe-exec" in _kinds(src), f"evasion not caught: {src!r}"


def test_import_form_exec_clean_negatives_2026_09_01():
    """Resolution must not over-fire: benign imports of same-named-but-safe
    functions stay silent."""
    hdr = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n"
    ok = [
        hdr + "from os import getcwd\n@mcp.tool()\ndef f():\n    return getcwd()",   # os.getcwd, not exec
        hdr + "from json import loads\n@mcp.tool()\ndef f(b):\n    return loads(b)",  # json.loads is safe
        hdr + "import os as o\n@mcp.tool()\ndef f():\n    return o.getpid()",
    ]
    for src in ok:
        assert "unsafe-exec" not in _kinds(src), f"false positive: {src!r}"


def test_unsafe_deser_fires_2026_09_01():
    """New class: pickle/yaml/marshal deserialization of untrusted bytes = RCE."""
    hdr = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n"
    bad = [
        hdr + "import pickle\n@mcp.tool()\ndef f(b):\n    return pickle.loads(b)",
        hdr + "from pickle import loads\n@mcp.tool()\ndef f(b):\n    return loads(b)",
        hdr + "import yaml\n@mcp.tool()\ndef f(b):\n    return yaml.load(b)",
        hdr + "import marshal\n@mcp.tool()\ndef f(b):\n    return marshal.loads(b)",
    ]
    for src in bad:
        assert "unsafe-deser" in _kinds(src), f"deser sink not caught: {src!r}"


def test_unsafe_deser_clean_negatives_2026_09_01():
    hdr = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n"
    ok = [
        hdr + "import yaml\n@mcp.tool()\ndef f(b):\n    return yaml.safe_load(b)",
        hdr + "import yaml\n@mcp.tool()\ndef f(b):\n    return yaml.load(b, Loader=yaml.SafeLoader)",
        hdr + "import json\n@mcp.tool()\ndef f(b):\n    return json.loads(b)",
    ]
    for src in ok:
        assert "unsafe-deser" not in _kinds(src), f"false positive: {src!r}"


def test_exec_family_and_getattr_evasions_0_0_14():
    """2026-09-01 audit critical #2/#3: os.exec*/spawn*/posix_spawn and
    pty.spawn are code-execution sinks the same as os.system, and
    getattr(os, 'system') / getattr(os, 'sys' + 'tem') is a constant-string
    lookup the resolver can fold. All must fire."""
    hdr = "from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n"
    cases = [
        hdr + "import os\n@mcp.tool()\ndef f(c):\n    os.execv(c, [c])",
        hdr + "import os\n@mcp.tool()\ndef f(c):\n    os.execvp('sh', ['sh', '-c', c])",
        hdr + "import os\n@mcp.tool()\ndef f(c):\n    os.spawnl(os.P_WAIT, c, c)",
        hdr + "import os\n@mcp.tool()\ndef f(c):\n    os.posix_spawn(c, [c], {})",
        hdr + "import pty\n@mcp.tool()\ndef f(c):\n    pty.spawn(c)",
        hdr + "import os\n@mcp.tool()\ndef f(c):\n    getattr(os, 'system')(c)",
        hdr + "import os\n@mcp.tool()\ndef f(c):\n    getattr(os, 'sys' + 'tem')(c)",
    ]
    for src in cases:
        assert "unsafe-exec" in _kinds(src), f"evasion not caught: {src!r}"
    # non-constant getattr stays a DECLARED blind spot, not a silent one
    src = hdr + "import os\n@mcp.tool()\ndef f(c, n):\n    getattr(os, n)(c)"
    assert "unsafe-exec" not in _kinds(src)


def test_syntax_error_reports_zero_checks_0_0_14():
    from arcaeon.prove.vet.checks import scan_source_ex
    findings, ran = scan_source_ex("def f(:\n  pass\n", "b.py")
    assert ran == []
    assert [f.check for f in findings] == ["parse"]
