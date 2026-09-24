"""Static checks over MCP server source. AST-based, no code execution.

WIP 2026-08-29. One class implemented end-to-end (unsafe-exec) plus ssrf and
zero-auth heuristics. Every finding carries file + line so it is verifiable, not
asserted. Precision-first: a check would rather miss than cry a false red.
"""
from __future__ import annotations

import ast
import inspect
import io
import math
import re
import tokenize
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    check: str          # "unsafe-exec" | "ssrf" | "path-traversal" | "zero-auth"
                        # | "secret-in-code" | "audit-record" | "unreceipted-allow"
    severity: str       # "high" | "medium" | "low" | "info"
    file: str
    line: int
    detail: str
    # Structured sub-result, used only where a finding is graded on a LADDER
    # rather than being simply present. `audit-record` (MCP08) carries the four
    # OWASP gates here so a reader sees the whole ladder, not just the rung that
    # failed. It is omitted from `as_dict()` when None ON PURPOSE: a `gates: null`
    # key on every finding would change the bytes of every previously emitted
    # grade artifact, and re-testability is the only thing this project sells.
    # (Frozen but not hashed anywhere — a dict field makes __hash__ unusable.)
    gates: dict | None = None
    # WHERE this site is reached FROM, when the defect and the entry point are
    # not the same place: [{"file", "line", "handler"}, ...], one entry per tool
    # handler whose call path reaches it. `file`/`line` above are the SITE (the
    # line a reader opens to see the bug); `via` is the route. Added 2026-09-04
    # for `except-returns-success`, which had been reporting the tool handler's
    # location as the finding's location and leaving the real line in prose: a
    # buyer opened the file:line and saw a handler with no `except` in it.
    #
    # ALWAYS A LIST, even for one handler, so a consumer never has to branch on
    # the count; when N handlers reach one site there is ONE finding carrying N
    # entries, not N findings.
    #
    # Omitted from `as_dict()` when None for exactly the reason `gates` is: a
    # `via: null` key on every finding would change the bytes of every grade
    # artifact ever emitted, and re-testability is the only thing this project
    # sells.
    via: list | None = None

    def as_dict(self) -> dict:
        d = asdict(self)
        if d.get("gates") is None:
            d.pop("gates", None)
        if d.get("via") is None:
            d.pop("via", None)
        return d


# --- the check registry ------------------------------------------------------
# THE list. `scan_source` runs it, and the grade artifact's `checks_run` is read
# off it (`check_names()`), so the artifact cannot claim a set the code does not
# execute. Added 2026-08-30 after exactly that drift: `path-traversal` shipped
# in 0.0.4 while every grade emitted since kept saying three classes — an error
# in the understating direction, which is the worst kind for a tool whose only
# product is an honest self-report.
#
# Adding a check = one decorated function. There is no second place to update,
# because a second place is where drift lives.

CHECKS: list = []


def register(name: str):
    """Register a check under the `check` name its findings carry. Every check
    takes the same (tree, rel, source) signature so the registry can call them
    uniformly; most ignore `source`."""
    def deco(fn):
        CHECKS.append((name, fn))
        return fn
    return deco


def check_names() -> list:
    """The check classes that actually run, in run order. The grade reads this."""
    return [name for name, _ in CHECKS]


# --- unsafe-exec: eval / exec / os.system / subprocess(..., shell=True) ------

_EXEC_NAMES = {"eval", "exec"}
# os.system / os.popen plus the whole process-replacement family. The 2026-09-01
# audit found os.execv("/bin/sh", ["sh", "-c", cmd]) graded clean because only
# the two shell-string spellings were in the set.
_OS_EXEC = {
    "system", "popen",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "posix_spawn", "posix_spawnp",
}
_PTY_EXEC = {"spawn"}                               # pty.spawn(cmd)
_SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}


def _const_str(node: ast.AST) -> str | None:
    """A string literal, or a `+`-chain of string literals ("sys" + "tem"),
    folded. None for anything not fully constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l, r = _const_str(node.left), _const_str(node.right)
        if l is not None and r is not None:
            return l + r
    return None


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        base = f.value.id if isinstance(f.value, ast.Name) else ""
        return f"{base}.{f.attr}" if base else f.attr
    # getattr(os, "system")(cmd) / getattr(os, "sys" + "tem")(cmd): the func is
    # itself a Call. Resolve it to the dotted spelling it stands for (2026-09-01
    # audit finding #2 — an indirect call the Name/Attribute branches never saw).
    if (isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr"
            and len(f.args) >= 2 and isinstance(f.args[0], ast.Name)):
        attr = _const_str(f.args[1])
        if attr is not None:
            return f"{f.args[0].id}.{attr}"
    return ""


def _import_bindings(tree: ast.AST) -> tuple[dict, dict]:
    """Resolve local names to canonical dotted sink identities, so the sink
    checks match by MEANING not by the exact spelling the authors typed.

    Closes the 2026-09-01 audit's fourth blind spot: `unsafe-exec` was
    name-shape matching (`from os import system` -> bare `system`, which no
    branch matched; `import os as o` -> `o.system`; `builtins.eval`), so a
    shell backdoor graded clean. We now build a name map from the module's
    own import statements and resolve every call through it.

    Returns (name_to_canon, module_alias):
      name_to_canon: local call-name -> canonical 'module.attr'
        from os import system         -> {'system': 'os.system'}
        from os import system as s     -> {'s': 'os.system'}
        from importlib import import_module -> {'import_module': 'importlib.import_module'}
      module_alias: local module name -> real dotted module
        import os as o                 -> {'o': 'os'}
        import subprocess as sp        -> {'sp': 'subprocess'}

    KNOWN LIMIT (honest, documented in BLIND_SPOTS): runtime REASSIGNMENT
    aliasing (`b = eval; b(x)`) is dataflow, not imports, and is NOT resolved
    here. A determined author can still dodge via a local variable rebind.
    Import-form evasion — the idiomatic, accidental-looking kind — is closed."""
    name_to_canon: dict[str, str] = {}
    module_alias: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    module_alias[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                if a.name == "*":
                    continue
                local = a.asname or a.name
                name_to_canon[local] = f"{node.module}.{a.name}"
    return name_to_canon, module_alias


def _canon_call(node: ast.Call, name_to_canon: dict, module_alias: dict) -> str:
    """The canonical sink identity of a call, resolved through imports.
    Bare `system` (from `from os import system`) -> 'os.system';
    `o.system` (from `import os as o`)          -> 'os.system';
    `builtins.eval`                              -> 'eval'."""
    raw = _call_name(node)
    if not raw:
        return ""
    if "." not in raw:
        return name_to_canon.get(raw, raw)
    base, attr = raw.split(".", 1)
    if base in module_alias:
        return f"{module_alias[base]}.{attr}"
    if base == "builtins":
        return attr
    return raw


def _has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


_SHELL_INVOKERS = {"sh", "bash", "zsh", "dash", " sh", "cmd", "powershell", "pwsh"}


def _first_arg_is_shell_list(node: ast.Call) -> bool:
    """subprocess.Popen(["sh", "-c", cmd]) — shell injection with shell=False,
    which the shell=True check misses. Detect a list first-arg whose head is a
    shell binary followed by -c. Found as a false negative on 2026-08-29 when
    the checker was run against a deliberately-vulnerable server before going
    public (the whole point of the WIP self-audit)."""
    if not node.args:
        return False
    first = node.args[0]
    if not isinstance(first, ast.List) or len(first.elts) < 2:
        return False
    head = first.elts[0]
    flag = first.elts[1]
    head_v = head.value if isinstance(head, ast.Constant) else ""
    flag_v = flag.value if isinstance(flag, ast.Constant) else ""
    prog = str(head_v).rsplit("/", 1)[-1].strip().lower()
    return prog in {s.strip() for s in _SHELL_INVOKERS} and str(flag_v).lower() in ("-c", "/c")


@register("unsafe-exec")
def check_unsafe_exec(tree: ast.AST, rel: str, source: str = "") -> list[Finding]:
    out: list[Finding] = []
    name_to_canon, module_alias = _import_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # `name` = canonical identity resolved through imports (os.system even
        # when written `from os import system`); `raw_short` = last component of
        # the literal spelling, kept for the subprocess branches which match any
        # module's run/Popen (subprocess is rarely aliased-away meaningfully).
        name = _canon_call(node, name_to_canon, module_alias)
        short = name.split(".")[-1]
        if name in _EXEC_NAMES:
            out.append(Finding("unsafe-exec", "high", rel, node.lineno,
                               f"call to builtin {name}() — arbitrary code execution surface"))
        elif name in (f"os.{n}" for n in _OS_EXEC):
            out.append(Finding("unsafe-exec", "high", rel, node.lineno,
                               f"{name}() runs a shell command string" if short in ("system", "popen")
                               else f"{name}() replaces/spawns a process from tool-reachable arguments"))
        elif name in (f"pty.{n}" for n in _PTY_EXEC):
            out.append(Finding("unsafe-exec", "high", rel, node.lineno,
                               f"{name}() spawns a process on a pty from tool-reachable arguments"))
        elif short in _SUBPROCESS_FUNCS and _has_shell_true(node):
            out.append(Finding("unsafe-exec", "high", rel, node.lineno,
                               f"subprocess.{short}(..., shell=True) — shell injection surface"))
        elif short in _SUBPROCESS_FUNCS and _first_arg_is_shell_list(node):
            out.append(Finding("unsafe-exec", "high", rel, node.lineno,
                               f"subprocess.{short}([shell, '-c', ...]) — shell invoked explicitly, shell=False does not save you"))
        elif _is_dynamic_import_exec(node, name_to_canon, module_alias):
            out.append(Finding("unsafe-exec", "high", rel, node.lineno,
                               "dynamic-import exec — __import__/import_module('os').system(...) evasion of the os-exec check"))
    return out


def _is_dynamic_import_exec(node: ast.Call, name_to_canon: dict | None = None,
                            module_alias: dict | None = None) -> bool:
    """Catch __import__('os').system(x) / importlib.import_module('subprocess').run(...),
    the dynamic-import dodge around the bare os.system name check. The call's
    func is an Attribute whose .value is itself a Call to a dynamic importer —
    either the builtin __import__ or importlib.import_module (resolved through
    this module's own imports, so `from importlib import import_module` and
    `import importlib as il; il.import_module(...)` both count)."""
    f = node.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr not in (_OS_EXEC | _SUBPROCESS_FUNCS | _EXEC_NAMES):
        return False
    base = f.value
    if not isinstance(base, ast.Call):
        return False
    inner = _canon_call(base, name_to_canon or {}, module_alias or {})
    return inner in ("__import__", "importlib.import_module")


# --- unsafe deserialization: pickle/yaml/marshal load of untrusted bytes ------
# Added 2026-09-01 (audit finding #4 — a whole RCE class with NO check). These
# are direct arbitrary-code-execution sinks when fed tool input; a server doing
# pickle.loads(arg) is as dangerous as one doing eval(arg). Resolved through the
# same import map so `from pickle import loads` does not walk past.
_DESER_SINKS = {"pickle.loads", "pickle.load", "marshal.loads", "marshal.load",
                "dill.loads", "dill.load", "cloudpickle.loads", "cloudpickle.load",
                "shelve.open", "jsonpickle.decode"}
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}


def _yaml_load_is_unsafe(node: ast.Call) -> bool:
    """yaml.load(x) is RCE unless a safe Loader is named. yaml.safe_load is fine."""
    for kw in node.keywords:
        if kw.arg == "Loader":
            v = kw.value
            nm = v.attr if isinstance(v, ast.Attribute) else (v.id if isinstance(v, ast.Name) else "")
            return nm not in _SAFE_YAML_LOADERS
    return True  # no Loader= -> full-power loader on older pyyaml, unsafe


@register("unsafe-deser")
def check_unsafe_deser(tree: ast.AST, rel: str, source: str = "") -> list[Finding]:
    out: list[Finding] = []
    name_to_canon, module_alias = _import_bindings(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _canon_call(node, name_to_canon, module_alias)
        if name in _DESER_SINKS:
            out.append(Finding("unsafe-deser", "high", rel, node.lineno,
                               f"{name}() deserializes untrusted bytes — arbitrary code execution surface"))
        elif name == "yaml.load" and _yaml_load_is_unsafe(node):
            out.append(Finding("unsafe-deser", "high", rel, node.lineno,
                               "yaml.load() without a safe Loader — arbitrary object construction (use yaml.safe_load)"))
    return out


# --- ssrf: outbound network call inside a tool handler -----------------------

_NET_CALLS = {"urlopen", "get", "post", "request", "Session", "urlretrieve"}
_TOOL_DECORATORS = {"tool", "resource"}   # FastMCP: @mcp.tool(), @app.tool()
# The LOW-LEVEL SDK spelling: `@server.call_tool()` / `@app.call_tool()` on the
# ONE function that dispatches every tool by name. Added 2026-09-04 after the
# reproduction run measured both reference Python servers (modelcontextprotocol
# servers/git and servers/fetch) reporting ZERO tool handlers: neither
# `_TOOL_DECORATORS` nor `_dispatch_handlers` matched them, so every check that
# walks OUT from a handler reported a zero that meant "never asked", not "clean".
#
# It is kept OUT of `_TOOL_DECORATORS` on purpose, and the reason is measured
# rather than aesthetic. `check_ssrf` matches a bare `get`/`post`/`request` as
# the last component of any dotted call, so the dispatcher's own
# `arguments.get("repo_path")` reads as an outbound network call: putting
# `call_tool` in the shared set turned servers/git from 0 findings into 10 false
# medium reds in one line. The dispatcher is therefore a handler ROOT (what the
# reachability walks start from) and not yet a taint SOURCE; closing the
# `_NET_CALLS` hole is its own change with its own evidence.
_DISPATCH_DECORATORS = frozenset({"call_tool"})


def _is_tool_handler(fn: ast.FunctionDef | ast.AsyncFunctionDef,
                     extra=frozenset()) -> bool:
    """Is `fn` registered as a tool handler by a decorator? `extra` adds
    spellings the caller accepts beyond the FastMCP set (see
    `_DISPATCH_DECORATORS`)."""
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        attr = target.attr if isinstance(target, ast.Attribute) else (
            target.id if isinstance(target, ast.Name) else "")
        if attr in _TOOL_DECORATORS or attr in extra:
            return True
    return False


def _tainted_names(fn) -> set:
    """Tool-input-derived names inside a handler: the parameters PLUS simple
    one-hop aliases (p = tool_arg). Closes the aliased-taint blind spot
    (2026-08-30) — `p = url; urlopen(p)` now traces back to the param."""
    params = {a.arg for a in fn.args.args}
    tainted = set(params)
    # Iterate to a fixpoint so chained aliases (a=p; b=a) all resolve.
    changed = True
    while changed:
        changed = False
        for sub in ast.walk(fn):
            if (isinstance(sub, ast.Assign) and len(sub.targets) == 1
                    and isinstance(sub.targets[0], ast.Name)
                    and isinstance(sub.value, ast.Name)
                    and sub.value.id in tainted
                    and sub.targets[0].id not in tainted):
                tainted.add(sub.targets[0].id)
                changed = True
    return tainted


def _arg_is_tainted(arg, tainted: set) -> bool:
    return isinstance(arg, ast.Name) and arg.id in tainted


# Keyword arguments that only an HTTP call takes. A `.get(...)` carrying one of
# these is a request whatever its receiver is called.
_HTTP_KWARGS = frozenset({"url", "headers", "params", "timeout", "json", "data",
                          "auth", "verify", "proxies", "cookies", "allow_redirects",
                          "follow_redirects", "stream", "cert"})


def _is_mapping_lookup(call: ast.Call) -> bool:
    """The `_NET_CALLS` hole named above, closed on its own evidence
    (2026-09-05): the verbatim mcp-atlassian `get_all_projects` handler
    (fixtures/mcp_atlassian_4067d1d, `servers/jira.py`) does
    `project.get("key")` on each result dict, and `check_ssrf` reported it as a
    medium "outbound network call" -- one false red on a stranger's file, the
    one cost this project cannot pay. The dispatcher's `arguments.get("repo_path")`
    on servers/git is the same shape.

    The shape of a mapping lookup, and only that shape, is skipped: the first
    positional argument is a plain string literal that is not a URL (no
    scheme, not a leading-slash path a base-URL client would resolve), and no
    HTTP-only keyword argument is present. `requests.get(url)` (a name, tainted
    or not), `requests.get("https://...")`, `client.get("/items")`, and
    `x.get("k", headers=h)` all still count."""
    if not call.args:
        return False
    first = call.args[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return False
    key = first.value
    if "://" in key or key.startswith("/"):
        return False
    if any(kw.arg in _HTTP_KWARGS for kw in call.keywords):
        return False
    return True


@register("ssrf")
def check_ssrf(tree: ast.AST, rel: str, source: str = "") -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_tool_handler(node):
            continue
        tainted = _tainted_names(node)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and _call_name(sub).split(".")[-1] in _NET_CALLS:
                if _is_mapping_lookup(sub):
                    continue
                is_tainted = any(_arg_is_tainted(a, tainted) for a in sub.args)
                sev = "high" if is_tainted else "medium"
                why = ("target derives from tool input" if is_tainted
                       else "outbound network call in a tool handler")
                out.append(Finding("ssrf", sev, rel, sub.lineno,
                                   f"{_call_name(sub)}() — {why}"))
    return out


# --- path-traversal: file read/write with tool input (blind spot -> class) ---

_FILE_OPENERS = {"open", "read_text", "read_bytes", "write_text", "write_bytes"}


@register("path-traversal")
def check_path_traversal(tree: ast.AST, rel: str, source: str = "") -> list[Finding]:
    """A tool handler passing tool input into open()/Path read-write is an
    arbitrary-file-access surface (../../etc/passwd). New check class added
    2026-08-30 — was a named blind spot in v0.0.3."""
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_tool_handler(node):
            continue
        tainted = _tainted_names(node)
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and _call_name(sub).split(".")[-1] in _FILE_OPENERS:
                if any(_arg_is_tainted(a, tainted) for a in sub.args):
                    out.append(Finding("path-traversal", "high", rel, sub.lineno,
                                       f"{_call_name(sub)}() opens a path derived from tool input — arbitrary file access"))
    return out


# --- zero-auth: a network transport bound with no auth in the file -----------

_AUTH_HINTS = ("auth", "token", "api_key", "apikey", "bearer", "verify_", "authorize")


@register("zero-auth")
def check_zero_auth(tree: ast.AST, rel: str, source: str = "") -> list[Finding]:
    out: list[Finding] = []
    lowered = source.lower()
    has_auth_hint = any(h in lowered for h in _AUTH_HINTS)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node).lower()
        # FastMCP: mcp.run(transport="sse"/"streamable-http"/"http")
        if name.endswith(".run") or name == "run":
            for kw in node.keywords:
                if kw.arg == "transport" and isinstance(kw.value, ast.Constant):
                    t = str(kw.value.value).lower()
                    if t in ("stdio",):
                        continue  # local pipe, no network exposure
                    if t and not has_auth_hint:
                        out.append(Finding("zero-auth", "high", rel, node.lineno,
                                           f"network transport {t!r} bound with no auth hint anywhere in the file"))
    return out


# --- secret-in-code (MCP01): a credential sitting in the source at rest ------
#
# Design: design/MCP01_secret_in_code.md (F4, 2026-08-30). The first four checks
# all ask "can this server be made to do something dangerous." This one asks a
# different question: is the server, right now, at rest, handing a credential to
# anyone who reads the file. Three pattern families, precision-first:
#   1. known-vendor key SHAPES  -> "high" (a prefix is a fingerprint, not a guess)
#   2. entropy-gated literal assigned to a secret-shaped NAME -> "medium"
#   3. .env-shaped NAME=value line quoted in a docstring or comment
# This is the class most exposed to noise, so the gates are deliberately mean:
# length, entropy, no whitespace, must mix letters and digits, placeholder
# vocabulary rejected, and vendor test/publishable prefixes exempt. What that
# costs in recall is written down in grade.py:BLIND_SPOTS with evidence.

_VENDOR_SHAPES = [
    ("AWS access key id",        re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS STS temp access key",  re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("Stripe live secret key",   re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe live restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    ("Stripe webhook signing secret", re.compile(r"\bwhsec_[0-9a-zA-Z]{24,}\b")),
    ("OpenAI project key",       re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI service-account key", re.compile(r"\bsk-svcacct-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI api key",           re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("GitHub token",             re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained PAT",  re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
]

# Meant to be public or meant to be hardcoded. Never flagged -- a false red on a
# fixture key is exactly the noise that gets a scanner uninstalled.
_PUBLIC_PREFIXES = ("sk_test_", "rk_test_", "pk_test_", "pk_live_", "whsec_test_")

_SECRET_NAME_RE = re.compile(r"(?i)(_KEY|_TOKEN|_SECRET|_CREDENTIAL|_PASSWORD|APIKEY|PASSWORD)$")
_SECRET_BARE_NAMES = {"authorization", "token", "secret", "password", "passwd",
                      "apikey", "api_key", "api-key", "x-api-key", "access_token"}
_AWS_SECRET_NAME_RE = re.compile(r"(?i)(aws_secret|secret_access_key)")
_AWS_SECRET_VALUE_RE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
_ENV_LINE_RE = re.compile(r"^([A-Z][A-Z0-9_]*)\s*=\s*(\S{8,})$")

# Vocabulary that means "fill this in," not "here is the key."
_PLACEHOLDER_HINTS = ("changeme", "change_me", "replace", "placeholder", "your",
                      "example", "sample", "dummy", "insert", "redacted", "todo",
                      "notreal", "xxxx", "aaaa", "<", ">", "${", "{{", "...")
_ENTROPY_MIN = 3.5
_SECRET_MIN_LEN = 16


def _entropy(s: str) -> float:
    """Shannon entropy in bits/char. ~3.5 is the common industry cutoff: high
    enough that 'changeme', 'REPLACE_ME' and 'xxxxxxxx' fall below it."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _is_public_shape(value: str) -> bool:
    return value.startswith(_PUBLIC_PREFIXES)


def _redact(secret: str) -> str:
    """A scanner that prints the key it found is a leak with a report attached."""
    head = secret[:6] if len(secret) > 10 else secret[:2]
    return f"{head}... ({len(secret)} chars)"


def _vendor_hits(value: str) -> list:
    if _is_public_shape(value.strip()):
        return []
    out = []
    for label, rx in _VENDOR_SHAPES:
        m = rx.search(value)
        if m and not any(m.group(0) == prev for _l, prev in out):
            out.append((label, m.group(0)))
    return out


def _is_secret_name(name: str) -> bool:
    n = name.strip()
    return bool(_SECRET_NAME_RE.search(n)) or n.lower() in _SECRET_BARE_NAMES


def _looks_like_a_live_secret(value: str) -> bool:
    """The entropy gate, plus the cheap structural gates that do most of the
    real precision work: a credential has no spaces, is not prose, is not a
    template, and in practice mixes letters and digits."""
    v = value.strip()
    if len(v) < _SECRET_MIN_LEN or any(ch.isspace() for ch in v):
        return False
    if _is_public_shape(v):
        return False
    low = v.lower()
    if any(h in low for h in _PLACEHOLDER_HINTS):
        return False
    if not (any(c.isalpha() for c in v) and any(c.isdigit() for c in v)):
        return False
    return _entropy(v) >= _ENTROPY_MIN


def _assign_name(target: ast.AST) -> str:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _named_string_constants(tree: ast.AST) -> dict:
    """id(Constant node) -> the name it is bound to. Covers plain assignment,
    annotated assignment, dict entries ({'Authorization': '...'}) and keyword
    arguments (Client(api_key='...')), all realistic leak sites."""
    named: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant):
                for t in node.targets:
                    nm = _assign_name(t)
                    if nm:
                        named[id(node.value)] = nm
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.value, ast.Constant):
                nm = _assign_name(node.target)
                if nm:
                    named[id(node.value)] = nm
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                        and isinstance(v, ast.Constant)):
                    named[id(v)] = k.value
        elif isinstance(node, ast.keyword):
            if node.arg and isinstance(node.value, ast.Constant):
                named[id(node.value)] = node.arg
    return named


def _comments(source: str) -> list:
    """(line, text) for every real comment token. Tokenized rather than regexed
    off the raw source so a '#' inside a string literal is not mistaken for a
    comment."""
    out = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                out.append((tok.start[0], tok.string.lstrip("#").strip()))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        pass  # a file that will not tokenize still parsed; just skip class 3b
    return out


def _offset_line(base_line: int, offset: int, max_offset: int) -> int:
    """A finding inside a multi-line literal points at the LEAKING line, not at
    the docstring's opening quote -- a line number that does not land on the
    secret makes the reader hunt, and every finding here is meant to be checked
    in five seconds. Clamped by the node's real source span so an escaped '\\n'
    inside a single-line literal cannot push the number past the literal."""
    return base_line + min(max(offset, 0), max(max_offset, 0))


def _env_line_findings(text: str, base_line: int, rel: str, max_offset: int = 0) -> list:
    """Class 3: a NAME=value line quoted inside source. A real key does not have
    to be ASSIGNED to leak -- a README block pasted into a module docstring, a
    'here is a working example' comment, both leak exactly as hard."""
    out = []
    for i, raw in enumerate(text.splitlines()):
        m = _ENV_LINE_RE.match(raw.strip())
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip("'\"")
        line = _offset_line(base_line, i, max_offset)
        hits = _vendor_hits(value)
        if hits:
            out.append(Finding("secret-in-code", "high", rel, line,
                               f"{hits[0][0]} quoted in an env-shaped line {name}=... "
                               f"({_redact(hits[0][1])}) -- credential embedded in source"))
        elif _is_secret_name(name) and _looks_like_a_live_secret(value):
            out.append(Finding("secret-in-code", "medium", rel, line,
                               f"env-shaped line {name}=... with a high-entropy value "
                               f"({_redact(value)}) quoted in source"))
    return out


@register("secret-in-code")
def check_secret_in_code(tree: ast.AST, rel: str, source: str = "") -> list[Finding]:
    named = _named_string_constants(tree)
    out: list[Finding] = []
    seen: set = set()

    def _add(f: Finding, key) -> None:
        if key in seen:
            return
        seen.add(key)
        out.append(f)

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        value = node.value
        name = named.get(id(node), "")
        span = (node.end_lineno or node.lineno) - node.lineno

        hits = _vendor_hits(value)
        if hits:
            for label, matched in hits:
                line = _offset_line(node.lineno,
                                    value[:value.find(matched)].count("\n"), span)
                _add(Finding("secret-in-code", "high", rel, line,
                             f"{label} literal in source ({_redact(matched)}) "
                             f"-- hard-coded credential"), (line, matched))
            continue

        # AWS secret access keys have no prefix to fingerprint: the bare 40-char
        # shape is base64 of anything, so it is gated on the name it is bound to.
        if (name and _AWS_SECRET_NAME_RE.search(name)
                and _AWS_SECRET_VALUE_RE.match(value.strip())):
            _add(Finding("secret-in-code", "high", rel, node.lineno,
                         f"AWS secret access key shape bound to {name} "
                         f"({_redact(value.strip())}) -- hard-coded credential"),
                 (node.lineno, value))
            continue

        if name and _is_secret_name(name) and _looks_like_a_live_secret(value):
            _add(Finding("secret-in-code", "medium", rel, node.lineno,
                         f"high-entropy literal assigned to {name} "
                         f"({_redact(value.strip())}) -- looks like a hard-coded credential"),
                 (node.lineno, value))
            continue

        if "\n" in value or _ENV_LINE_RE.match(value.strip()):
            for f in _env_line_findings(value, node.lineno, rel, span):
                _add(f, (f.line, f.detail))

    for line_no, text in _comments(source):
        for f in _env_line_findings(text, line_no, rel):
            _add(f, (f.line, f.detail))

    return sorted(out, key=lambda f: f.line)


# --- audit-record (MCP08): does a tool call leave a verifiable record? ------
#
# Design: design/MCP08_audit_record.md (board B2, 2026-08-30). Research:
# projects/online_business/BATCH100_R_OWASP_MCP08_2026-08-30.md.
#
# Every other check here asks "can this server be made to do something
# dangerous"; secret-in-code asks "is it leaking at rest". This one asks a third
# question: if it DID something, could anyone prove what. That is OWASP MCP08
# (Lack of Audit and Telemetry), and it is the differentiator — Snyk Agent
# Scan's ~21 issue codes contain zero audit/telemetry checks, because MCP08 is
# about a CONTROL BEING PRESENT rather than a bug being absent, which is awkward
# for a vulnerability scanner and natural for a grade.
#
# Four gates, one finding per server, severity = the FIRST gate not met:
#   1 presence          -- a tool call produces a record at all      -> high
#   2 completeness      -- tool name + timestamp + args/digest       -> medium
#   3 tamper-evidence   -- chain / hmac / ledger, not a plain log    -> medium
#   4 reconstructability-- a verify/replay path exists               -> low
#   all four met                                                     -> silence
#
# Precision rules, which are the whole game: print() is never a record; a
# logging call that does not name the tool is not a record; and the check only
# runs on a file that is actually a deployed server (a handler or a tools/call
# dispatcher AND an entrypoint). Everything is AST, never a text scan — the
# zero-auth check's whole-file substring test is our own worst blind spot (the
# word "author" in a docstring silences it), and mcp_vet/server.py mentions
# "mcp_vet.grade.verify()" inside a tool DESCRIPTION string, which a text scan
# would happily count as gate 4.

_LOG_METHODS = {"info", "warning", "warn", "error", "exception", "critical",
                "debug", "log"}
_LOGGERISH_RE = re.compile(r"(?i)log")
# Deliberately tight. "op", "action", "method" and "name" are NOT accepted as
# the tool-name field even though a dispatcher's `name` usually IS the tool
# name: too many records use those keys for something else, and a false green
# on gate 2 is worse than a stated miss.
_TOOL_FIELDS = {"tool", "tool_name", "toolname", "tool_invoked", "tool_called"}
_TS_FIELDS = {"ts", "timestamp", "timestamp_utc", "occurred_at", "created_at",
              "logged_at", "recorded_at", "event_time", "asctime"}
_TS_CALLS = {"time", "time_ns", "now", "utcnow", "isoformat", "strftime"}
_ARG_FIELDS = {"args", "arguments", "params", "parameters", "input", "inputs",
               "payload", "request", "args_digest", "input_digest", "args_hash",
               "input_hash", "argument_digest", "arg_digest"}
_APPEND_SINKS = {"append", "record", "emit", "log_event", "write_record",
                 "append_record", "add_record", "write_event"}
_LEDGERISH_RE = re.compile(r"(?i)(ledger|journal|audit|chain|trail|log|record)")
_DB_INSERT_CALLS = {"insert_one", "insert_many", "insert"}
_SQL_EXEC_CALLS = {"execute", "executemany", "execute_many"}
_OTEL_CALLS = {"start_as_current_span", "start_span", "add_event",
               "set_attribute", "record_exception"}
_ENTRY_CALLS = {"run", "serve", "main", "run_server", "serve_forever",
                "run_stdio", "stdio_server", "run_async"}
_VERIFY_RE = re.compile(r"(?i)^_?(verify|replay|reconstruct|audit_check|"
                        r"check_chain|validate_chain|attest)")
_CHAIN_FIELD_RE = re.compile(r"(?i)(chain|prev_hash|previous_hash|head_hash|"
                             r"last_hash|signature|hmac|merkle)")
_LINK_NAME_RE = re.compile(r"(?i)(prev|head|last|link|tip)")
_HASH_CALLS = {"sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}
_LEDGER_MODULE_RE = re.compile(r"(?i)(ledger|immudb|trillian|sigstore|worm|"
                               r"append_only|auditlog|audit_log|opentelemetry)")


def _short(call: ast.Call) -> str:
    return _call_name(call).split(".")[-1]


def _receiver_name(call: ast.Call) -> str:
    """The thing the method was called ON: `logger` in logger.info(...),
    `logger` in self.logger.info(...), `log` in log.append(...)."""
    f = call.func
    if not isinstance(f, ast.Attribute):
        return ""
    v = f.value
    if isinstance(v, ast.Name):
        return v.id
    if isinstance(v, ast.Attribute):
        return v.attr
    if isinstance(v, ast.Call):
        return _short(v)
    return ""


def _words(text: str) -> set:
    return {w.lower() for w in re.split(r"[^A-Za-z0-9_]+", text) if w}


def _string_words(node: ast.AST) -> set:
    out: set = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out |= _words(sub.value)
    return out


def _idents(node: ast.AST) -> set:
    out: set = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            out.add(sub.id.lower())
        elif isinstance(sub, ast.Attribute):
            out.add(sub.attr.lower())
        elif isinstance(sub, ast.keyword) and sub.arg:
            out.add(sub.arg.lower())
    return out


def _dispatch_handlers(tree: ast.AST) -> list:
    """Hand-rolled JSON-RPC dispatchers. Not every MCP server uses the SDK's
    decorators — arcaeon-ledger's speaks the protocol directly, and a check that
    only understands @mcp.tool() would score the reference implementation of the
    control it is testing for as having no tool handlers at all.

    The literal must be BRANCHED ON (`if method == "tools/call"`) or matched in a
    `case`, not merely present. A client, or a test that drives a server, builds
    `{"method": "tools/call"}` as a dict VALUE and dispatches nothing; the first
    repo-wide precision sweep caught exactly that and called a test file a server
    with no audit trail. Sending the message is not handling it."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(node):
            branched = (
                isinstance(sub, ast.Compare)
                and any(isinstance(c, ast.Constant) and c.value == "tools/call"
                        for c in sub.comparators)
            ) or (
                isinstance(sub, ast.MatchValue)
                and isinstance(sub.value, ast.Constant)
                and sub.value.value == "tools/call"
            )
            if branched:
                out.append(node)
                break
    return out


def _has_entrypoint(tree: ast.AST) -> bool:
    """Does this file actually SERVE? A module that defines a handler and never
    runs is a fragment, and asking a fragment where its audit trail is, is
    noise. Confessed as a gap: handlers in tools.py with run() in __main__.py
    are never asked the question."""
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            t = node.test
            if (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name)
                    and t.left.id == "__name__"):
                return True
        if isinstance(node, ast.Call) and _short(node) in _ENTRY_CALLS:
            return True
    return False


# --- reachability: where a handler's record is allowed to hide ---------------
#
# Until 0.0.17 the walk followed calls to functions defined in the same file
# and nothing else, by short name. Five honest recording shapes therefore
# graded "no record": a recorder imported from a sibling module, a bare
# `@audited` decorator (a Name, not a Call, so ast.walk never saw a call),
# base-class / mixin methods reached through `self`, construction-time
# middleware, and a wrapped dispatcher. The resolver below opens each of those
# ONE deliberate way; what it still cannot open is written into
# grade.MCP08_REACH_BLIND_SPOTS, one sentence per shape, with a fixture each.
#
# Sibling modules are opened only when the caller supplies a package directory
# (service.scan_target does, for a directory target; a single-file grade never
# does, because a verdict that depended on bytes the receipt's sha256 does not
# cover would not reproduce from the receipt).

_MIDDLEWARE_CALLS = {"middleware", "add_middleware", "use"}
_DISPATCH_ATTRS = {"call_tool"}
_MAX_ANCESTORS = 4     # how far above the handler's dir an absolute import may anchor
_SELF_NAMES = {"self", "cls"}
# `get_jira_fetcher` / `jira_client` / `make_confluence_fetcher`. Used ONLY to
# propose a class name that must then resolve like any other name; a factory
# whose class is nowhere in sight binds nothing.
_FACTORY_NAME_RE = re.compile(
    r"(?i)^(?:get|make|build|create|new|_get|_make|_build|_create|_new)?_?"
    r"(?P<stem>[a-z0-9_]*?)_(?P<kind>fetcher|client)$")


@dataclass
class _Mod:
    """One parsed module and the lookups the walk needs, built once."""
    tree: ast.AST
    funcs: dict      # name -> def, file-wide, first definition wins (as before)
    classes: dict    # name -> ClassDef
    owner: dict      # id(method def) -> the ClassDef it sits in
    imports: dict    # local name -> (module, attr or None, relative level)
    # The directory this module was READ FROM. A relative import (`from .projects
    # import ProjectsMixin`) anchors at the directory of the file that WRITES it,
    # not at the graded file's directory; before 2026-09-04 every relative import
    # anchored at the graded file's directory, so a sibling module's own
    # relative imports resolved to nothing the moment the sibling lived in a
    # different package directory. None for a tree parsed from a string.
    dir: Path | None = None


def _mod_from_tree(tree: ast.AST, mod_dir: Path | None = None) -> _Mod:
    funcs, classes, owner, imports = {}, {}, {}, {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.setdefault(node.name, node)
        elif isinstance(node, ast.ClassDef):
            classes.setdefault(node.name, node)
            for m in node.body:
                if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    owner[id(m)] = node
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                imports[a.asname or a.name] = (node.module or "", a.name, node.level)
        elif isinstance(node, ast.Import):
            for a in node.names:
                # `import pkg.audit as au` binds au -> pkg.audit; a bare
                # `import pkg.audit` binds pkg, and the chain is read at the call.
                imports[a.asname or a.name.split(".")[0]] = (
                    a.name if a.asname else a.name.split(".")[0], None, 0)
    return _Mod(tree, funcs, classes, owner, imports, mod_dir)


def _dotted(node: ast.AST) -> list:
    """`pkg.audit.record` -> ["pkg", "audit", "record"]; [] if not a plain chain."""
    parts: list = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return []
    parts.append(node.id)
    return parts[::-1]


def _methods(cls: ast.ClassDef) -> list:
    return [m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]


class _Walker:
    """Resolves names to definitions for one scan: this file first, then a
    sibling module named by an import, when a package directory was given.
    Every module opened is remembered so the file-level gates (tamper
    evidence, verify path) can look inside it too."""

    def __init__(self, tree: ast.AST, package_dir=None):
        self.pkg = Path(package_dir) if package_dir else None
        self.root = _mod_from_tree(tree, self.pkg)
        self._cache: dict = {}
        self.opened: list = []      # [_Mod] sibling modules actually parsed
        self._binds: dict = {}      # id(fn) -> (bound instances, unresolved names)

    # -- modules ------------------------------------------------------------
    def module(self, dotted: str, level: int, base_dir: Path | None = None):
        """The _Mod for an import target, or None (no package dir, not found,
        unparseable). Relative imports anchor at the IMPORTING module's own
        directory (`base_dir`, which falls back to the graded file's);
        absolute ones at the nearest ancestor whose name is the first segment,
        falling back to that same directory (script-style imports)."""
        anchor = base_dir or self.pkg
        if anchor is None:
            return None
        parts = [p for p in dotted.split(".") if p]
        if level:
            base = anchor
            for _ in range(level - 1):
                base = base.parent
            bases = [base]
        else:
            bases = []
            anc = anchor
            for _ in range(_MAX_ANCESTORS):
                if parts and anc.name == parts[0]:
                    bases.append(anc.parent)
                    break
                if anc.parent == anc:
                    break
                anc = anc.parent
            bases.append(anchor)
        for base in bases:
            stem = base.joinpath(*parts) if parts else base
            for cand in (stem.with_suffix(".py") if parts else None, stem / "__init__.py"):
                if cand is not None and cand.is_file():
                    return self._load(cand)
        return None

    def _load(self, path: Path):
        key = str(path.resolve())
        if key not in self._cache:
            try:
                mod = _mod_from_tree(
                    ast.parse(path.read_text(encoding="utf-8", errors="replace")),
                    path.parent)
            except (SyntaxError, OSError):
                mod = None
            self._cache[key] = mod
            if mod is not None:
                self.opened.append(mod)
        return self._cache[key]

    def imported(self, mod: _Mod, name: str):
        """(def-or-class, its _Mod) for a name bound by an import in `mod`."""
        binding = mod.imports.get(name)
        if binding is None or binding[1] is None:
            return None
        module, attr, level = binding
        target = self.module(module, level, mod.dir)
        if target is None:
            return None
        node = target.funcs.get(attr) or target.classes.get(attr)
        return (node, target) if node is not None else None

    # -- names --------------------------------------------------------------
    def resolve(self, expr: ast.AST, mod: _Mod, cls=None, classes: bool = False,
                instances: dict | None = None) -> list:
        """Definitions a call/decorator/argument expression stands for, as
        [(node, _Mod)]. Functions always; classes only when `classes` is set
        (a middleware registration or a base list wants the class, a call in
        a handler body does not). `self.x` / `cls.x` inside a method resolves
        against that class and its direct bases and NOTHING else: the old
        file-wide fallback made every same-named method look reachable.

        `instances` (optional) maps a LOCAL name to the class it was bound to
        by a factory call, so `jira.get_all_projects()` after
        `jira = await get_jira_fetcher(ctx)` resolves into that class's method.
        See `instance_bindings`."""
        if isinstance(expr, ast.Call):
            expr = expr.func
        parts = _dotted(expr)
        if not parts:
            return []
        if len(parts) == 1:
            return self._by_name(parts[0], mod, classes)
        if parts[0] in _SELF_NAMES and cls is not None and len(parts) == 2:
            return self._method(cls, mod, parts[1])
        if instances and len(parts) == 2 and parts[0] in instances:
            icls, imod = instances[parts[0]]
            return self._method(icls, imod, parts[1])
        binding = mod.imports.get(parts[0])
        if binding is not None and binding[1] is None:            # module alias
            target = self.module(".".join([binding[0]] + parts[1:-1]), 0, mod.dir)
            if target is not None:
                return self._by_name(parts[-1], target, classes)
        if binding is not None and binding[1] is not None:        # `from . import audit`
            target = self.module(".".join([binding[0], binding[1]] + parts[1:-1]),
                                 binding[2], mod.dir)
            if target is not None:
                return self._by_name(parts[-1], target, classes)
        fn = mod.funcs.get(parts[-1])          # the pre-0.0.17 short-name fallback
        return [(fn, mod)] if fn is not None else []

    def _by_name(self, name: str, mod: _Mod, classes: bool) -> list:
        if name in mod.funcs:
            return [(mod.funcs[name], mod)]
        if classes and name in mod.classes:
            return [(mod.classes[name], mod)]
        hit = self.imported(mod, name)
        if hit is None or (isinstance(hit[0], ast.ClassDef) and not classes):
            return []
        return [hit]

    def _method(self, cls: ast.ClassDef, mod: _Mod, name: str) -> list:
        """`self.name` -> the method on this class, else on a DIRECT base
        (one level, same file or same package). Grandparents are a stated
        blind spot."""
        for m in _methods(cls):
            if m.name == name:
                return [(m, mod)]
        out = []
        for base in cls.bases:
            for bcls, bmod in self.resolve(base, mod, classes=True):
                if isinstance(bcls, ast.ClassDef):
                    out += [(m, bmod) for m in _methods(bcls) if m.name == name]
        return out

    # -- instances held in a local ------------------------------------------
    #
    # The shape this exists for, measured 2026-09-04 against sooperset/mcp-atlassian
    # (projects/online_business/mcp_vet_rule_reproduction_2026-09-04.md): a tool
    # handler never names the class that does the work. It asks a factory for one:
    #
    #     jira = await get_jira_fetcher(ctx)
    #     projects = jira.get_all_projects(include_archived=include_archived)
    #
    # `jira` is a local bound to a call's return value, so the resolver saw a
    # dotted expression whose head was neither an import nor `self`, and the walk
    # stopped at the handler. On that repo it stopped 52 times out of 53: every
    # body in the fetcher layer, which is where that server puts the code any
    # handler-rooted check is looking for.
    #
    # Three ways a class is pinned, all of them requiring a definition we can
    # actually open, never a guess:
    #   1. the callee resolves to a def with an ANNOTATED return type that names
    #      a class (`async def get_jira_fetcher(ctx) -> JiraFetcher`);
    #   2. the callee resolves to a def whose body RETURNS A CONSTRUCTOR call
    #      (`return JiraFetcher(config=cfg)`), the annotation-free spelling;
    #   3. the callee IS a class (`fetcher = JiraFetcher(cfg)`).
    # A factory-shaped NAME (`get_*_fetcher`, `*_client`, `*_fetcher`) is used
    # only to look for a class the CALLER can already see by name; a name that
    # resolves to nothing binds nothing.
    #
    # Everything else is counted, not guessed: a local bound from a call we
    # cannot open, and later used as a receiver, is tallied so the coverage line
    # can report the not-looked-at rather than let it read as clean.

    def instance_bindings(self, fn, mod: _Mod) -> tuple[dict, set]:
        """({local -> (ClassDef, _Mod)}, {locals bound from a call we could not
        open}) for one function body. Cached per body: a body is walked once."""
        key = id(fn)
        if key in self._binds:
            return self._binds[key]
        bound: dict = {}
        unresolved: set = set()
        for node in _own_nodes(fn, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            value = node.value
            if isinstance(value, ast.Await):
                value = value.value
            if not isinstance(value, ast.Call):
                continue
            name = node.targets[0].id
            hit = self._class_of_call(value, mod)
            if hit is not None:
                bound[name] = hit
                unresolved.discard(name)
            elif name not in bound:
                unresolved.add(name)
        self._binds[key] = (bound, unresolved)
        return self._binds[key]

    def _class_of_call(self, call: ast.Call, mod: _Mod):
        """(ClassDef, _Mod) the return value of `call` is known to be, or None."""
        direct = [(n, m) for n, m in self.resolve(call, mod, classes=True)
                  if isinstance(n, ast.ClassDef)]
        if direct:
            return direct[0]                                   # 3. a constructor
        for target, tmod in self.resolve(call, mod):
            if not isinstance(target, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if target.returns is not None:                     # 1. the annotation
                hit = self._class_of_annotation(target.returns, tmod)
                if hit is not None:
                    return hit
            for ret in _own_nodes(target, ast.Return):         # 2. the constructor
                if not isinstance(ret.value, ast.Call):
                    continue
                for n, m in self.resolve(ret.value, tmod, classes=True):
                    if isinstance(n, ast.ClassDef):
                        return (n, m)
        return self._class_by_factory_name(call, mod)

    def _class_of_annotation(self, node: ast.AST, mod: _Mod, depth: int = 0):
        """The class an annotation names: `JiraFetcher`, `"JiraFetcher"` (a
        forward reference), `JiraFetcher | None`, `Optional[JiraFetcher]`.
        A container annotation (`list[dict[str, Any]]`) resolves to nothing,
        which is the point: only a class we can open counts."""
        if depth > 3 or node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            try:
                node = ast.parse(node.value, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            for side in (node.left, node.right):
                hit = self._class_of_annotation(side, mod, depth + 1)
                if hit is not None:
                    return hit
            return None
        if isinstance(node, ast.Subscript):
            base = _dotted(node.value)
            if base and base[-1] in ("Optional", "Union", "Annotated"):
                inner = node.slice
                elts = inner.elts if isinstance(inner, ast.Tuple) else [inner]
                for e in elts:
                    hit = self._class_of_annotation(e, mod, depth + 1)
                    if hit is not None:
                        return hit
            return None
        for n, m in self.resolve(node, mod, classes=True):
            if isinstance(n, ast.ClassDef):
                return (n, m)
        return None

    def _class_by_factory_name(self, call: ast.Call, mod: _Mod):
        """Last resort, and deliberately weak: a factory-SHAPED name is turned
        into the class name it implies (`get_jira_fetcher` -> `JiraFetcher`) and
        that name is looked up the ordinary way. If the caller cannot see such a
        class, this binds nothing: the name alone is never evidence."""
        raw = _call_name(call).split(".")[-1]
        m = _FACTORY_NAME_RE.match(raw)
        if not m:
            return None
        stem, kind = m.group("stem"), m.group("kind")
        camel = "".join(p[:1].upper() + p[1:] for p in stem.split("_") if p)
        for cand in (camel + kind[:1].upper() + kind[1:], camel):
            if not cand:
                continue
            for n, mm in self._by_name(cand, mod, classes=True):
                if isinstance(n, ast.ClassDef):
                    return (n, mm)
        return None


def _call_sites(fn: ast.AST):
    """Every expression in `fn` that may transfer control to a definition we
    can open: calls (which covers `with x():` items and `@deco(...)`), plus
    bare decorators, which are Names, not Calls, and were never followed."""
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            yield sub
        elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in sub.decorator_list:
                if not isinstance(d, ast.Call):
                    yield d


def _flatten(node, walker: _Walker, mod: _Mod) -> list:
    """Roots for a middleware argument: a function, or every method of a
    class (`add_middleware(AuditMiddleware())`, `middleware=[Audit()]`)."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return [r for e in node.elts for r in _flatten(e, walker, mod)]
    out = []
    for target, tmod in walker.resolve(node, mod, classes=True):
        if isinstance(target, ast.ClassDef):
            out += [(m, tmod) for m in _methods(target)]
        else:
            out.append((target, tmod))
    return out


def _middleware_roots(walker: _Walker) -> list:
    """Construction-time recorders that no handler calls: `server.middleware(f)`
    / `add_middleware(Audit())` / `use(f)`, a `middleware=[...]` keyword at
    construction, `@server.middleware` on a function, and a rebound dispatcher
    (`server.call_tool = audited(server.call_tool)`). A subclass overriding
    call_tool is NOT here; that one is confessed, not scored."""
    mod, out = walker.root, []
    for node in ast.walk(mod.tree):
        if isinstance(node, ast.Call):
            if _short(node) in _MIDDLEWARE_CALLS:
                for a in node.args:
                    out += _flatten(a, walker, mod)
            for k in node.keywords:
                if k.arg == "middleware":
                    out += _flatten(k.value, walker, mod)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                name = _dotted(d.func if isinstance(d, ast.Call) else d)
                if name and name[-1] in _MIDDLEWARE_CALLS:
                    out.append((node, mod))
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Attribute) and t.attr in _DISPATCH_ATTRS
                   for t in node.targets):
                out += _flatten(node.value, walker, mod)
    return out


def _merge_origins(origins: dict, target, source_key: int) -> None:
    """Carry the roots that reach `source_key` onto `target`, deduped by node
    identity and order-preserving (a finding's `via` list has to be stable
    across runs or the grade stops reproducing)."""
    have = origins.setdefault(id(target), [])
    seen = {id(f) for f, _m in have}
    for f, m in origins.get(source_key, ()):
        if id(f) not in seen:
            have.append((f, m))
            seen.add(id(f))


def _reachable(starts: list, walker: _Walker, max_depth: int = 2,
               instances: bool = False, counters: dict | None = None,
               origins: dict | None = None) -> list:
    """Handler bodies plus what they reach, <= max_depth hops: same-file
    helpers, same-package imports, bare decorators, `self.` methods on the
    class or a direct base. The audit write almost always lives in an
    `_audit(...)` helper rather than inline in every handler, so a
    one-body-only walk would report "no record" on the most common correct
    shape. `starts` and the result are [(def, _Mod)].

    `instances=True` additionally follows a method call on a local that a
    factory returned (`jira = await get_jira_fetcher(ctx); jira.method()`) into
    that class's method; see `_Walker.instance_bindings`. It is opt-in because
    it widens the reachable set, and a check that already ships its verdicts on
    this walk must not have them move underneath it. `counters`, when given,
    accumulates `unresolved_instance_calls`: a receiver bound from a call we
    could NOT open, so the miss is reported rather than read as clean.

    `origins`, when given, is filled with id(body) -> [(start def, its _Mod)]:
    every START this body was reached from. It is what lets a finding report the
    defect's own file:line and still say which tool handler(s) get there
    (`Finding.via`). Depth-complete for the two hops this walk takes, because a
    whole frontier level is expanded before the next one begins; a body first
    seen at depth 2 is never expanded, so a root that only reaches it through
    that body is not propagated further. Stated rather than papered over."""
    seen = {id(f): (f, m) for f, m in starts}
    if origins is not None:
        for f, m in starts:
            here = origins.setdefault(id(f), [])
            if not any(id(f) == id(g) for g, _m in here):
                here.append((f, m))            # a start is its own origin
    frontier, depth = list(seen.values()), 0
    while frontier and depth < max_depth:
        nxt = []
        for fn, mod in frontier:
            cls = mod.owner.get(id(fn))
            binds: dict = {}
            if instances:
                binds, unknown = walker.instance_bindings(fn, mod)
                if counters is not None and unknown:
                    for site in _call_sites(fn):
                        parts = _dotted(site.func if isinstance(site, ast.Call) else site)
                        if len(parts) == 2 and parts[0] in unknown:
                            counters["unresolved_instance_calls"] = counters.get(
                                "unresolved_instance_calls", 0) + 1
            for site in _call_sites(fn):
                for tgt, tmod in walker.resolve(site, mod, cls, instances=binds):
                    if origins is not None:
                        _merge_origins(origins, tgt, id(fn))
                    if id(tgt) not in seen:
                        seen[id(tgt)] = (tgt, tmod)
                        nxt.append((tgt, tmod))
        frontier, depth = nxt, depth + 1
    return list(seen.values())


def _open_is_append(call: ast.Call) -> bool:
    modes = [a for a in call.args[1:2]] + [k.value for k in call.keywords if k.arg == "mode"]
    for m in modes:
        if isinstance(m, ast.Constant) and isinstance(m.value, str) and "a" in m.value:
            return True
    return False


def _sql_is_insert(call: ast.Call) -> bool:
    if not call.args:
        return False
    a = call.args[0]
    text = a.value if isinstance(a, ast.Constant) and isinstance(a.value, str) else ""
    if isinstance(a, ast.JoinedStr):
        text = "".join(v.value for v in a.values
                       if isinstance(v, ast.Constant) and isinstance(v.value, str))
    return text.strip().lower().startswith("insert")


def _record_kind(call: ast.Call, host_names: set) -> str:
    """What kind of call record this call writes, or "" for none.

    A print() is stdout, not an audit trail. A logging call only counts if it
    NAMES the tool — a log line that cannot tell you which tool ran cannot
    answer the question MCP08 asks."""
    short, recv = _short(call), _receiver_name(call)
    if short == "print":
        return ""
    if short in _LOG_METHODS and recv and _LOGGERISH_RE.search(recv):
        toks = _idents(call) | _string_words(call)
        if toks & _TOOL_FIELDS or (toks & host_names):
            return "logging call naming the tool"
        return ""
    if short == "open" and _open_is_append(call):
        return "append-mode file write"
    if short in _DB_INSERT_CALLS:
        return "db %s()" % short
    if short in _SQL_EXEC_CALLS and _sql_is_insert(call):
        return "db INSERT"
    if short in _OTEL_CALLS or recv in ("tracer", "span"):
        return "OpenTelemetry span"
    if short in _APPEND_SINKS and recv and _LEDGERISH_RE.search(recv):
        return "ledger-style %s.%s()" % (recv, short)
    return ""


def _record_fields(fn: ast.AST, evidence: list) -> set:
    """Field names visible in the record-writing function: dict keys, keyword
    argument names, assignment targets, plus the words of any format string
    handed to a logging call (a log line "tool=%s args=%s ts=%s" carries the
    fields as literally as a dict does)."""
    names: set = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Dict):
            for k in sub.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    names.add(k.value.lower())
        elif isinstance(sub, ast.keyword) and sub.arg:
            names.add(sub.arg.lower())
        elif isinstance(sub, ast.Assign):
            for t in sub.targets:
                n = _assign_name(t)
                if n:
                    names.add(n.lower())
        elif isinstance(sub, ast.AnnAssign):
            n = _assign_name(sub.target)
            if n:
                names.add(n.lower())
    for call in evidence:
        names |= _string_words(call)
    return names


def _has_timestamp(fn: ast.AST, names: set) -> bool:
    if names & _TS_FIELDS:
        return True
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call) and _short(sub) in _TS_CALLS:
            return True
    return False


def _tamper_evidence(tree: ast.AST):
    """(what, line) if a silent edit to the record would be detectable.

    An append-mode open() deliberately does NOT count. OWASP lists "append-only
    or write-once media" under this gate, but a plain open(p,"a") is one letter
    from a rewrite and statically indistinguishable from WORM storage; counting
    it would let a plain unchained log pass gate 3, which contradicts the whole
    severity ladder."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names]
            if isinstance(node, ast.ImportFrom) and node.module:
                mods.append(node.module)
            for m in mods:
                if m and _LEDGER_MODULE_RE.search(m):
                    return ("ledger/append-only library %r" % m, node.lineno)
                if m == "hmac" or (m or "").endswith(".hmac"):
                    return ("hmac", node.lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                        and _CHAIN_FIELD_RE.search(k.value)):
                    return ("record field %r" % k.value, node.lineno)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                n = _assign_name(t)
                if n and _CHAIN_FIELD_RE.search(n):
                    return ("chain variable %r" % n, node.lineno)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # A SHA-2 call is only a CHAIN when something links records: the
            # same function has to name a prev/head/last/link. sha256 of a blob
            # is a checksum, not tamper-evidence.
            hashes = [s for s in ast.walk(node)
                      if isinstance(s, ast.Call) and _short(s) in _HASH_CALLS]
            if hashes and any(_LINK_NAME_RE.search(i) for i in _idents(node)):
                return ("hash chained to a previous record in %s()" % node.name,
                        hashes[0].lineno)
    return None


def _reconstructable(tree: ast.AST):
    """(what, line) if an independent party could replay the record set.

    AST only. mcp_vet/server.py's own tool description contains the sentence
    "Feed it back to mcp_vet.grade.verify()" — a text scan would award this gate
    for a sentence, which is exactly how the zero-auth substring test got its
    blind spot."""
    for node in ast.walk(tree):
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and _VERIFY_RE.match(node.name)):
            return ("%s()" % node.name, node.lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _VERIFY_RE.match(_short(node)):
            return ("call to %s()" % _short(node), node.lineno)
    return None


_GATE_LADDER = [("presence", "high"), ("completeness", "medium"),
                ("tamper_evidence", "medium"), ("reconstructability", "low")]


def _audit_roots(tree: ast.AST) -> list:
    """Every function a tool call can enter: decorator-registered handlers
    (FastMCP's `@mcp.tool()` AND the low-level `@server.call_tool()`), plus
    hand-rolled `tools/call` dispatchers."""
    handlers = [n for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and _is_tool_handler(n, _DISPATCH_DECORATORS)]
    seen_ids = {id(h) for h in handlers}
    return handlers + [d for d in _dispatch_handlers(tree) if id(d) not in seen_ids]


def audit_record_applies(source: str) -> bool:
    """Would `audit-record` ASK this file the question? True only for a file
    with tool handlers AND an entrypoint. An empty finding list means "all four
    gates met" for such a file and "question not applicable" for any other; a
    consumer that reads [] as a clean bill for a test file has graded a test
    file (the registry benchmark did, on its own first run, 2026-09-02)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    return bool(_audit_roots(tree)) and _has_entrypoint(tree)


@register("audit-record")
def check_audit_record(tree: ast.AST, rel: str, source: str = "",
                       package_dir=None) -> list[Finding]:
    roots = _audit_roots(tree)
    if not roots or not _has_entrypoint(tree):
        return []   # not a deployed server; the question does not apply

    host_names = {r.name.lower() for r in roots}
    walker = _Walker(tree, package_dir)
    # Middleware and a wrapped dispatcher run on every call without any
    # handler naming them, so they start the walk alongside the handlers.
    starts = [(r, walker.root) for r in roots] + _middleware_roots(walker)
    bodies = [fn for fn, _m in _reachable(starts, walker, max_depth=2)]
    # The file-level gates look wherever the walk actually went: a chain kept
    # in the sibling module that writes the record is the same chain.
    trees = [tree] + [m.tree for m in walker.opened]

    writers: list = []          # (fn, [calls], [labels])
    for fn in bodies:
        calls, labels = [], []
        for sub in ast.walk(fn):
            if isinstance(sub, ast.Call):
                kind = _record_kind(sub, host_names)
                if kind:
                    calls.append(sub)
                    labels.append(kind)
        if calls:
            writers.append((fn, calls, labels))

    presence = bool(writers)
    missing_fields: list = []
    completeness = False
    for fn, calls, _labels in writers:
        names = _record_fields(fn, calls)
        want = [("tool name", bool(names & _TOOL_FIELDS)),
                ("timestamp", _has_timestamp(fn, names)),
                ("args/input digest", bool(names & _ARG_FIELDS))]
        if all(ok for _n, ok in want):
            completeness = True
            missing_fields = []
            break
        if not missing_fields:
            missing_fields = [n for n, ok in want if not ok]

    tamper = next((t for t in map(_tamper_evidence, trees) if t), None)
    recon = next((r for r in map(_reconstructable, trees) if r), None)
    gates = {"presence": presence, "completeness": completeness,
             "tamper_evidence": tamper is not None,
             "reconstructability": recon is not None}

    unmet = [(g, sev) for g, sev in _GATE_LADDER if not gates[g]]
    if not unmet:
        return []
    gate_name, severity = unmet[0]

    if presence:
        first = min(c.lineno for _f, cs, _l in writers for c in cs)
        seen_labels = sorted({l for _f, _c, ls in writers for l in ls})
        wrote = "records a call at line %d (%s)" % (first, "; ".join(seen_labels))
    else:
        first = min(r.lineno for r in roots)
        wrote = ("no call record on any tool-handling path (%d handler(s), "
                 "first at line %d)" % (len(roots), first))

    why = {
        "presence": "a tool call leaves nothing behind to reconstruct",
        "completeness": "the record is missing " + ", ".join(missing_fields or ["fields"]),
        "tamper_evidence": ("the record is a plain log: no hash chain, hmac, "
                            "signature or append-only store, so a silent edit "
                            "or deletion is undetectable"),
        "reconstructability": ("no verify/replay path, so nobody can prove the "
                               "record set is intact"),
    }[gate_name]
    gate_no = [g for g, _ in _GATE_LADDER].index(gate_name) + 1
    detail = ("OWASP MCP08 audit trail: %s; gate %d (%s) unmet: %s"
              % (wrote, gate_no, gate_name.replace("_", "-"), why))
    return [Finding("audit-record", severity, rel, first, detail, gates)]


# --- unreceipted-allow: PASS verdicts carry no receipt -----------------------
#
# Design: design/unreceipted_allow.md (2026-08-30). NOT an OWASP MCP Top 10
# number -- this is not one of the ten official categories, and inventing one
# would be exactly the kind of overclaim this project's whole pitch argues
# against. It is a refinement of the same territory as MCP08 (audit-record):
# that check asks "does a tool call leave ANY record"; this one asks a sharper
# question about a GATE function specifically -- "when it says yes, does the
# yes leave the same kind of proof the no does."
#
# The shape: a policy/gate function returns a verdict on both branches (an
# ALLOW and a BLOCK), and the BLOCK branch is receipted (a hash/digest/audit
# field) while the ALLOW branch is bare. That is backwards from what an audit
# trail is FOR -- the whole point is proving what was PERMITTED, not padding
# the paper trail on the refusals nobody needs convincing about. A gate built
# this way makes every permitted action unreplayable and only refusals
# provable, which inverts the accountability the receipt was supposed to buy.
#
# Structural, not semantic: this reads dict-literal `return` statements only,
# classifies each by a verdict field (a boolean field named allow/allowed/
# pass/passed/permit/permitted/grant/granted/approve/approved, or a string
# field named verdict/decision holding an allow- or block-shaped word), and
# checks for a receipt-shaped KEY in the same dict -- same field-name
# discipline check_audit_record uses for its completeness gate, not a values
# scan. Two verdicts (>=1 allow, >=1 block) must appear as *direct* returns of
# the SAME function -- not a nested closure's returns, which is why this walks
# the function body itself rather than `ast.walk(fn)` (that would also credit
# a nested helper's own returns to the outer gate).

_VERDICT_BOOL_FIELDS = {"allow", "allowed", "pass", "passed", "permit",
                        "permitted", "grant", "granted", "approve", "approved"}
_VERDICT_STR_FIELDS = {"verdict", "decision"}
_ALLOW_WORDS = {"allow", "allowed", "pass", "passed", "approve", "approved",
                "permit", "permitted", "grant", "granted"}
_BLOCK_WORDS = {"block", "blocked", "deny", "denied", "reject", "rejected",
                "refuse", "refused", "forbid", "forbidden"}
_RECEIPT_FIELD_NAMES = {"receipt", "receipt_id", "hash", "digest", "audit",
                        "audit_id", "record", "record_id", "proof",
                        "signature", "hmac", "chain", "ledger_id", "witness",
                        "evidence", "trace_id", "audit_hash"}


def _dict_str_items(d: ast.Dict):
    for k, v in zip(d.keys, d.values):
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            yield k.value.lower(), v


def _gate_verdict(d: ast.Dict) -> str:
    """"allow" / "block" / "" for a verdict dict-literal, read off ONE
    deliberately-tight field per class -- same discipline as MCP08's
    _TOOL_FIELDS: a generic 'ok'/'status'/'result' name is left out on purpose
    because those get reused for unrelated success/failure in plain code, and
    a false gate-classification here is a false red on a stranger's file."""
    for key, v in _dict_str_items(d):
        if key in _VERDICT_STR_FIELDS and isinstance(v, ast.Constant) and isinstance(v.value, str):
            low = v.value.lower()
            if low in _ALLOW_WORDS:
                return "allow"
            if low in _BLOCK_WORDS:
                return "block"
        elif key in _VERDICT_BOOL_FIELDS and isinstance(v, ast.Constant) and isinstance(v.value, bool):
            return "allow" if v.value else "block"
    return ""


def _receipt_fields(d: ast.Dict) -> set:
    return {k for k, _v in _dict_str_items(d) if k in _RECEIPT_FIELD_NAMES}


def _own_returns(fn) -> list:
    """Return statements belonging to `fn` directly -- NOT to a nested def or
    lambda inside it. A plain `ast.walk(fn)` would attribute a closure's own
    allow/block returns to the outer gate, which is a different function with
    a different receipt story."""
    out: list = []
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Return):
            out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


@register("unreceipted-allow")
def check_unreceipted_allow(tree: ast.AST, rel: str, source: str = "") -> list[Finding]:
    out: list[Finding] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        allows, blocks = [], []
        for ret in _own_returns(fn):
            if not isinstance(ret.value, ast.Dict):
                continue
            verdict = _gate_verdict(ret.value)
            if not verdict:
                continue
            fields = _receipt_fields(ret.value)
            (allows if verdict == "allow" else blocks).append((ret.lineno, fields))
        if not allows or not blocks:
            continue  # not a two-outcome gate in THIS function -- nothing to compare
        bare_allows = [(ln, f) for ln, f in allows if not f]
        receipted_blocks = [(ln, f) for ln, f in blocks if f]
        if not (bare_allows and receipted_blocks):
            continue
        block_line, block_fields = receipted_blocks[0]
        carried = ", ".join(sorted(block_fields))
        for ln, _f in bare_allows:
            out.append(Finding(
                "unreceipted-allow", "high", rel, ln,
                f"allow/pass verdict returned with no receipt/hash/audit field, "
                f"while the block/deny verdict at line {block_line} carries "
                f"{carried} -- every permitted action is unreplayable, only "
                f"refusals are proven"))
    return out


# --- except-returns-success: a failure path hands back a success shape -------
#
# Gate 2, 2026-09-04 (projects/online_business/GATE2_THIRD_VERDICT_MCP_SERVERS_
# 2026-09-04.md) ran the whole "vacuous pass" rule family against six real MCP
# servers, 66,909 non-test lines, and opened all 196 hits by hand. ONE idiom of
# the seven cleared the 30% real gate: an exception handler that returns a
# success-shaped value which reaches a tool result with no error marker, 20 real
# of 57 opened (35.1%). The other six contributed ONE real hit across 139:
# except-swallow 1/101, all-empty 0/22, default-true 0/8, the lint's own
# except-true 0/3, absence-pass 0/3, catch-null 0/2. They are deliberately NOT
# shipped. On this population they are noise, and noise on a stranger's file is
# the one cost this project cannot pay.
#
# The mechanism, verbatim from the worst real case (mcp-atlassian
# jira/projects.py:49): a fetcher catches bare Exception, logs it, and returns
# []. The tool wrapper one layer up (servers/jira.py:3390) has a careful
# `except (MCPAtlassianAuthenticationError, HTTPError, OSError, ValueError)`
# that would have reported the failure properly, and it never fires, because
# the layer below already converted the failure into an answer. The agent
# receives `json.dumps([])` and reads it as "there are no projects."
#
# Why reachability is IN the rule rather than a later refinement: the identical
# `return []` in a helper nobody serves is a contract, not a lie, and the gate's
# arguable pile (25 of 57) was mostly fetchers no tool reaches yet. So this
# walks OUT from the tool handlers, through the same _Walker / _reachable the
# audit-record check uses, and a body no handler reaches is never asked the
# question.
#
# Three exclusions, each one a FALSE hit the gate paid for by hand (section 5):
#   (a) the returned dict carries its own error marker (`error`, `isError`,
#       `errors`, `success: False`, `ok: False`). Five hits in
#       jira/attachments.py were `return {"success": False, "error": msg}`, the
#       exact opposite of the defect: a handler reporting its third verdict.
#   (b) the polarity is documented. All three of the lint's own hits were
#       fail-closed `return True`s where True is the SAFE answer and the author
#       had said so in a comment. The heuristic is ported from
#       scripts/vacuous_pass_lint.py's `_documented` (that file lives outside
#       this package and cannot be imported by a shipped wheel): polarity words,
#       OR a substantive comment block, because the better a comment is the more
#       ways it has to miss a keyword list.
#   (c) the handler re-raises, or hands back the caught exception itself. Both
#       are the failure being reported, not converted.
#
# A third state is not a success shape either: a dict or list literal holding
# `None` models "the lookup did not run" (supabase-mcp api-platform.ts:381 does
# exactly this with `undefined`) and is left alone.

_SUCCESS_CONSTRUCTORS = {"list", "dict", "tuple", "set", "str"}
_ERROR_MARKER_KEYS = {"error", "iserror", "errors"}
# `success`/`ok` are error markers only when the literal says False. A bare
# `{"ok": True}` out of an exception handler is the defect, not the exclusion.
_FALSE_MARKER_KEYS = {"success", "ok"}

# Ported from scripts/vacuous_pass_lint.py (2026-09-03). Deliberately loose:
# the point is not to grade the prose, it is to tell "someone reasoned about the
# direction" from "a bare return nobody has ever justified".
_POLARITY_WORDS = ("fail-open", "fail open", "fail-closed", "fail closed",
                   "refus", "don't block", "do not block", "never block",
                   "assume", "treat as", "deliberate", "on purpose",
                   "better to", "safe", "skip", "unavailable", "degraded")
_POLARITY_MIN_CHARS = 60    # a substantive comment block IS the evidence
_POLARITY_NEAR = 2          # lines either side of the return that count as "at" it


def _own_nodes(fn, kind) -> list:
    """Nodes of type `kind` belonging to `fn` directly, NOT to a nested def or
    lambda inside it. Same traversal discipline as `_own_returns` above, which
    is left exactly as it is because it belongs to a shipped check; this one
    takes the node type as an argument because this check needs handlers,
    raises and returns from the same walk."""
    out: list = []
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, kind):
            out.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return out


def _is_none(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _error_marked(d: ast.Dict) -> bool:
    """Exclusion (a): the literal reports its own failure."""
    for key, value in _dict_str_items(d):
        flat = key.replace("_", "")
        if flat in _ERROR_MARKER_KEYS:
            return True
        if (flat in _FALSE_MARKER_KEYS and isinstance(value, ast.Constant)
                and value.value is False):
            return True
    return False


def _success_shape(node: ast.AST | None) -> str | None:
    """How this returned value reads to a caller that got no error, or None if
    it does not read as a success at all. `None` itself is not a success shape:
    returning it is the catch-null idiom, 0 real of 2 opened at gate 2."""
    if isinstance(node, ast.Constant):
        if node.value is True:
            return "True"
        if isinstance(node.value, str) and node.value == "":
            return '""'
        return None
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        kind = {ast.List: "list", ast.Tuple: "tuple", ast.Set: "set"}[type(node)]
        if any(_is_none(e) for e in node.elts):
            return None                      # a None inside models "did not look"
        return ("an empty %s" % kind) if not node.elts else ("a %s literal" % kind)
    if isinstance(node, ast.Dict):
        if _error_marked(node) or any(_is_none(v) for v in node.values):
            return None
        return "{}" if not node.keys else "a dict literal"
    if isinstance(node, ast.Call):
        short = _call_name(node).split(".")[-1]
        if short in _SUCCESS_CONSTRUCTORS and not node.args and not node.keywords:
            return "%s()" % short
        if len(node.args) == 1 and not node.keywords:
            inner = _success_shape(node.args[0])
            if inner is not None:
                return "%s(%s)" % (short, inner)
    return None


def _polarity_documented(source: str, handler: ast.ExceptHandler,
                         ret: ast.Return) -> bool:
    """Exclusion (b). A comment within `_POLARITY_NEAR` lines of the return, or
    anywhere inside the handler, that says which way this fails. Comments are
    read from the tokenizer (`_comments`), so a '#' inside a string is not one.
    Strings in the returned value count too: `return [], "index unavailable"`
    states its polarity in the value it hands back."""
    lo = min(handler.lineno, ret.lineno) - _POLARITY_NEAR
    hi = max(getattr(handler, "end_lineno", None) or handler.lineno,
             ret.lineno + _POLARITY_NEAR)
    blob: list = []
    chars = 0
    for line, text in _comments(source):
        if lo <= line <= hi:
            blob.append(text)
            chars += len(text)
    if ret.value is not None:
        for sub in ast.walk(ret.value):
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                blob.append(sub.value)
    low = " ".join(blob).lower()
    return any(w in low for w in _POLARITY_WORDS) or chars >= _POLARITY_MIN_CHARS


def _catches_keyerror(h: ast.ExceptHandler) -> bool:
    """`except KeyError:` or a tuple that names it. A bare `except:` does not
    count: it catches everything, so nothing about the try block can make it
    dead."""
    t = h.type
    if t is None:
        return False
    names = t.elts if isinstance(t, ast.Tuple) else [t]
    return any(isinstance(n, ast.Name) and n.id == "KeyError" for n in names)


def _get_default_only_body(try_node: ast.Try) -> bool:
    """True when every dict access in this try block is `.get()` WITH a default
    and there is no subscript at all, so no `KeyError` can be raised out of it.

    Deliberately narrow, and it is a PROXY, not a proof: it reads the block's
    own statements only (a call into another function can still raise KeyError
    anywhere, and that call's body is not read here). It exists to put a number
    beside the confession that this walk cannot tell a reachable `except` from
    a dead one, which is why the count is REPORTED and never subtracted from
    anything."""
    saw_get = False
    for stmt in try_node.body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Subscript):
                return False        # a subscript can raise; the clause is live
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and len(node.args) == 2 and not node.keywords):
                saw_get = True
    return saw_get


def _dead_keyerror_candidates(fn) -> int:
    """How many `except KeyError` clauses in this body sit over a try block
    whose only dict accesses are `.get()`-with-default. See
    `_get_default_only_body` for why this is a proxy and not a verdict, and
    `grade._FR_EXCEPT_DEAD` for the measured case it stands in for
    (`confluence/comments.py:380`, driven with a malformed payload and never
    lit, while its subscripting sibling at `:150` lit on the first try)."""
    n = 0
    for try_node in _own_nodes(fn, ast.Try):
        if not _get_default_only_body(try_node):
            continue
        n += sum(1 for h in try_node.handlers if _catches_keyerror(h))
    return n


def _except_success_hits(fn, source: str) -> tuple[list, int]:
    """(hits, handlers examined) for one function body. A hit is
    (except handler, return node, shape)."""
    handlers = _own_nodes(fn, ast.ExceptHandler)
    hits: list = []
    for h in handlers:
        if _own_nodes(h, ast.Raise):
            continue                         # (c) the handler re-raises
        caught = {h.name} if h.name else set()
        for ret in _own_nodes(h, ast.Return):
            if ret.value is None:
                continue
            names = {n.id for n in ast.walk(ret.value) if isinstance(n, ast.Name)}
            if names & caught:
                continue                     # (c) hands back the caught exception
            shape = _success_shape(ret.value)
            if shape is None:
                continue
            if _polarity_documented(source, h, ret):
                continue                     # (b)
            hits.append((h, ret, shape))
    return hits, len(handlers)


def _scan_root(rel: str, package_dir) -> Path | None:
    """The directory `rel` is relative TO. `package_dir` is the graded file's own
    directory and `rel` is its path from the scan root, so the root is the one
    walked back up by however many directories `rel` carries."""
    if package_dir is None:
        return None
    root = Path(package_dir)
    for _ in range(len(Path(rel).parts) - 1):
        root = root.parent
    return root


def _rel_site(path: str, root: Path | None) -> str:
    """A sibling module's path the way a reader will type it: relative to the
    scan root, forward slashes. Never absolute (an absolute path in a finding
    would change the bytes of the grade with the checkout directory), and never
    climbing out of the root; a path the root does not contain is reduced to its
    basename rather than emitted as `../..`."""
    p = Path(path)
    if root is not None:
        try:
            return str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
        except (ValueError, OSError):
            pass
    return p.name


def _except_success_scan(tree: ast.AST, rel: str, source: str,
                         package_dir=None) -> tuple[list[Finding], dict]:
    """(findings, coverage). Coverage is counted whether or not anything fires:
    a check that reports only its hits cannot tell "nothing to find" from "I
    never looked", which is the same third verdict this check is about.

    WHERE A FINDING POINTS (changed 2026-09-04, and it is the whole point of
    this pass). `file` and `line` are the EXCEPT SITE: the module the converting
    body lives in, relative to the scan root, and the line of the RETURN inside
    the except handler. The return, not the `except`, for two reasons: it is the
    line that states the lie, and it is the line gate 2 recorded, so the numbers
    stay comparable to the population this check was measured against.

    Before this, a cross-file finding carried the TOOL HANDLER's file:line and
    left the real site in prose ("in get_page_comments() at line 160 of
    comments.py"). Measured on mcp-atlassian: 26 findings, 26 distinct sites,
    every one of them pointing a reader at a handler with no `except` in it. The
    handler now travels in `Finding.via` as structure instead of narration.

    ONE FINDING PER SITE. A fetcher method reached from forty handlers is one
    defect, not forty; its `via` carries all forty and coverage counts it once.
    (The walk already deduped bodies by identity; the explicit key also merges
    the case where the same file is opened both as the graded module and as a
    sibling of itself.)"""
    coverage = {"tool_handlers": 0, "bodies_examined": 0,
                "except_handlers_examined": 0, "files_unparsed": 0,
                "unresolved_instance_calls": 0,
                "dead_keyerror_candidates": 0,
                "sites_reported": 0, "handlers_reaching": 0}
    roots = _audit_roots(tree)
    coverage["tool_handlers"] = len(roots)
    if not roots:
        return [], coverage

    walker = _Walker(tree, package_dir)
    origins: dict = {}
    reached = _reachable([(r, walker.root) for r in roots], walker, max_depth=2,
                         instances=True, counters=coverage, origins=origins)
    coverage["bodies_examined"] = len(reached)
    # A sibling module that would not parse is a place this check could not
    # look. It is counted, not silently treated as clean.
    coverage["files_unparsed"] = sum(1 for m in walker._cache.values() if m is None)
    # id(_Mod) -> the path it was read from, inverted out of the walker's own
    # cache so a sibling body can be named without _Walker having to carry it.
    mod_paths = {id(m): p for p, m in walker._cache.items() if m is not None}
    sources: dict = {}
    scan_root = _scan_root(rel, package_dir)

    # (file, line) -> [detail, [via entry, ...]]. Insertion-ordered, so the
    # findings come out in walk order and the grade reproduces byte for byte.
    sites: dict = {}
    for fn, mod in reached:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        in_file = mod is walker.root
        if in_file:
            body_source = source
        else:
            path = mod_paths.get(id(mod))
            if path is None:
                continue                     # cannot read it, cannot judge it
            if path not in sources:
                try:
                    sources[path] = Path(path).read_text(encoding="utf-8",
                                                         errors="replace")
                except OSError:
                    sources[path] = None
            body_source = sources[path]
            if body_source is None:
                continue
        hits, examined = _except_success_hits(fn, body_source)
        coverage["except_handlers_examined"] += examined
        # Counted over every body the walk entered, whether or not it fired:
        # the number is about what could not be told apart, not about what was
        # reported. Nothing below reads it.
        coverage["dead_keyerror_candidates"] += _dead_keyerror_candidates(fn)
        if not hits:
            continue
        # The tool handler(s) this body is reached from, as structure. Roots all
        # come from the graded tree, so their file is `rel`; the lookup is
        # written generally anyway rather than assuming it.
        via = []
        for root_fn, root_mod in origins.get(id(fn), ()):
            via.append({
                "file": rel if root_mod is walker.root
                        else _rel_site(mod_paths.get(id(root_mod), ""), scan_root),
                "line": root_fn.lineno,
                "handler": getattr(root_fn, "name", ""),
            })
        for _h, ret, shape in hits:
            if in_file:
                site_file = rel
                where = "in %s()" % fn.name
            else:
                site_file = _rel_site(mod_paths[id(mod)], scan_root)
                where = "in %s() at line %d of %s" % (
                    fn.name, ret.lineno, Path(mod_paths[id(mod)]).name)
            key = (site_file, ret.lineno)
            if key in sites:
                _merge_via(sites[key][2], via)      # same site, another route
            else:
                sites[key] = [shape, where, list(via)]

    # Details are composed HERE, after every route into a site is known, so the
    # "and N more" in the sentence cannot go stale behind a later merge.
    out: list[Finding] = []
    for (site_file, line), (shape, where, via) in sites.items():
        out.append(Finding(
            "except-returns-success", "medium", site_file, line,
            "exception handler returns %s with no error marker, %s, on a path a "
            "tool handler reaches (%s): the failure is handed back as a "
            "successful result and the caller cannot tell it apart from a real "
            "answer" % (shape, where, _via_phrase(via)),
            None, via or None))
    coverage["sites_reported"] = len(out)
    coverage["handlers_reaching"] = len({
        (v["file"], v["line"]) for _s, _w, via in sites.values() for v in via})
    return out, coverage


def _via_phrase(via: list) -> str:
    """The `via` list said in words, for the detail sentence: the finding names
    both ends in prose AND carries the route as structure. One handler is named;
    the rest are counted, because a detail string forty handlers long is not
    read by anybody."""
    if not via:
        return "handler unknown"
    first = "reached from %s() at %s:%d" % (via[0]["handler"], via[0]["file"],
                                            via[0]["line"])
    if len(via) == 1:
        return first
    return "%s and %d more tool handler(s)" % (first, len(via) - 1)


def _merge_via(have: list, more: list) -> None:
    """Union two route lists in place, order preserved, deduped on the triple."""
    seen = {(v["file"], v["line"], v["handler"]) for v in have}
    for v in more:
        key = (v["file"], v["line"], v["handler"])
        if key not in seen:
            have.append(v)
            seen.add(key)


@register("except-returns-success")
def check_except_returns_success(tree: ast.AST, rel: str, source: str = "",
                                 package_dir=None) -> list[Finding]:
    """An except handler on a tool-reachable path that converts a failure into a
    successful-looking value. The finding points at the EXCEPT SITE (the module
    it lives in, relative to the scan root, and the line of the `return` inside
    the handler); the tool handler that reaches it travels in `via`. See
    `_except_success_scan` for why."""
    return _except_success_scan(tree, rel, source, package_dir)[0]


def except_success_coverage(source: str, rel: str = "<source>",
                            package_dir=None) -> dict:
    """What the check actually looked at: tool handlers found, bodies walked,
    except handlers read, files it could not parse, and calls made on an
    instance whose class the walk could not pin. Printed as a counts line by
    `python -m arcaeon.prove.vet scan`, because a coverage number nobody reads is the kind
    of artifact this project keeps promising not to write.

    `unresolved_instance_calls` (2026-09-04) is the honest half of the
    factory-binding fix: a receiver bound from a call we could open resolves and
    is walked; one we could not open is COUNTED, never guessed at, so the reader
    can see how much of the server the walk declined to enter.

    `sites_reported` / `handlers_reaching` (2026-09-04) are the dedup made
    visible: findings are one per except SITE, and a site reached from several
    tool handlers is one finding carrying several `via` entries. Printed as
    "N site(s) via M handler(s)" so the finding count and the handler count can
    never be silently confused for each other.

    `dead_keyerror_candidates` (2026-09-04) is the number beside the newest
    confession: `except KeyError` clauses whose try block has no subscript in it
    and at least one `.get()`-with-default, which is the shape of a clause that
    can never fire. It is a PROXY, it is REPORTED and never subtracted from the
    finding count, and the rule's behaviour does not change because of it. See
    `grade._FR_EXCEPT_DEAD`: the runtime run on mcp-atlassian found exactly this
    at `confluence/comments.py:380`, reported like any other site and unable to
    execute."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {"tool_handlers": 0, "bodies_examined": 0,
                "except_handlers_examined": 0, "files_unparsed": 1,
                "unresolved_instance_calls": 0,
                "dead_keyerror_candidates": 0,
                "sites_reported": 0, "handlers_reaching": 0}
    return _except_success_scan(tree, rel, source, package_dir)[1]


def _takes_package_dir(check) -> bool:
    return "package_dir" in inspect.signature(check).parameters


def scan_source_ex(source: str, rel: str,
                   package_dir=None) -> tuple[list[Finding], list[str]]:
    """Run all checks over one source string. Returns (findings, checks that
    ACTUALLY ran). On a syntax error ZERO checks run and the second element is
    [] — the grade must read its `checks_run` off this, never off the registry,
    or an unparseable file with a backdoor in it gets a receipt saying every
    check looked (2026-09-01 audit, critical #1).

    `package_dir` is the directory the file lives in, when the caller has one
    (a tree scan). It is handed only to checks that declare the parameter:
    today that is `audit-record`, which opens sibling modules an import
    names. Without it every check is single-file, as before."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [Finding("parse", "info", rel, e.lineno or 0, f"could not parse: {e.msg}")], []
    out: list[Finding] = []
    ran: list[str] = []
    for name, check in CHECKS:
        if package_dir is not None and _takes_package_dir(check):
            out.extend(check(tree, rel, source, package_dir=package_dir))
        else:
            out.extend(check(tree, rel, source))
        ran.append(name)
    return out, ran


def scan_source(source: str, rel: str) -> list[Finding]:
    """Findings only — see scan_source_ex for the checks-that-ran half."""
    return scan_source_ex(source, rel)[0]


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    """One file's findings, routed by EXTENSION.

    The routing is new on 2026-09-04 and it closes a plain bug: `scan_file` was
    Python-only, so `python -m arcaeon.prove.vet scan index.ts` handed TypeScript to
    `ast.parse` and printed "could not parse: closing parenthesis ')' does not
    match opening parenthesis '{'". A user following the README's own example on
    a `.ts` file was told their file was broken, got no TypeScript check, and got
    no coverage line. Only `grade_source` routed; `scan` did not.

    A single file is graded ALONE on both front ends: no `package_dir`, no
    sibling resolver. That is the same discipline `grade` already keeps: a
    verdict that depended on bytes the receipt does not pin would not reproduce
    from the receipt."""
    rel = str(path.relative_to(root)) if root else str(path)
    source = path.read_text(encoding="utf-8", errors="replace")
    from . import ts_checks          # local: ts_checks imports from this module
    if ts_checks.is_ts_path(path.name):
        return ts_checks.scan_source_ts_ex(source, rel)[0]
    return scan_source(source, rel)
