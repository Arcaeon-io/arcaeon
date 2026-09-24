"""The TypeScript / JavaScript front end: `audit-record` (OWASP MCP08) and,
since 2026-09-04, `except-returns-success`.

Why this file exists (2026-09-02): the registry benchmark. A 300-row smoke of
the official MCP registry showed npm packages outnumbering PyPI ones 32 to 1.
A Python-only scanner grading "the registry" would grade a rounding error of it
and the published number would be about the wrong population. So the one check
that is this project's differentiator gets a second front end, for the language
most of the population is written in.

Same four gates, same severity ladder, same `Finding` shape, same field
vocabulary (imported from `checks.py` so there is ONE list of what counts as a
tool-name / timestamp / args field, not two that drift). What differs is the
parser: tree-sitter instead of `ast`, behind an optional extra (`pip install
'arcaeon[ts]'`) because the base package's zero-dependency promise is
part of its pitch and this module must not break it. If tree-sitter is absent,
`available()` is False and callers must report the file as NOT SCANNED --
never as clean.

SCOPE, stated so the grade cannot overclaim: this front end runs TWO checks as
of 2026-09-04, `audit-record` and `except-returns-success`. The other six
classes (unsafe-exec, ssrf, ...) have no TS implementation yet;
`scan_source_ts_ex` returns exactly the checks that ran, and it is those two.

Handler shapes recognised (the SDK's public surface as of 2026-09):
  server.tool(name, ..., handler)             McpServer high-level API
  server.registerTool(name, config, handler)  McpServer, newer form
  server.setRequestHandler(CallToolRequestSchema, handler)  low-level Server
  server.addTool({ name, execute })           fastmcp (TS port)
  @Tool({ name }) async add(args) {}          NestJS-style class method (mcp-nest)
An entrypoint is a `.connect(` (transport) or `.listen(` call anywhere in the
file; a file with handlers and no entrypoint is a fragment and gets no finding
(same narrowing as the Python check, same confession).

Where the record may live (0.0.17). The handler body is the start, and the
walk follows, to the same depth-2 cap as the Python check:
  - a local helper called by name (0.0.16);
  - a WRAPPER around the handler: `server.tool(n, s, withAudit(fn))`,
    `const h = withAudit(fn)`, `this.add.bind(this)`. The wrapper's own body
    is walked as well as the wrapped function, because that is where a
    wrapper-style recorder writes;
  - a DECORATOR on a class-method handler: `@Audited()` above `@Tool()`. The
    decorator factory's body (including the function it returns) is walked;
  - a RELATIVE IMPORT, when the caller hands in a resolver: `import { record }
    from "./audit"` / `"./audit.js"` / `require("./audit")` is followed into
    the sibling file IF `resolve(spec)` returns its source. Sibling files are
    parsed once per scan; their own imports are NOT followed (one level).
    Without a resolver (a single-string grade) nothing crosses the file, and
    a bare `record(...)` from an unresolved import is what it always was:
    unobserved, reported as absent. The tamper-evidence and reconstructability
    gates read the imported siblings too, so a chain + verifier that live next
    to the recorder count. A finding whose only record is in a sibling says so
    in its detail (`in ./audit.js`); its `line` stays in the graded file.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable, Optional

from .checks import (Finding, _ARG_FIELDS, _CHAIN_FIELD_RE, _GATE_LADDER,
                     _LEDGER_MODULE_RE, _LEDGERISH_RE, _LINK_NAME_RE,
                     _TOOL_FIELDS, _TS_FIELDS, _VERIFY_RE,
                     _merge_via, _via_phrase)

try:  # optional extra; absence is a NOT-SCANNED, never a clean
    import tree_sitter as _ts
    import tree_sitter_typescript as _tst
except Exception:  # pragma: no cover - exercised only when the extra is absent
    _ts = None
    _tst = None


def available() -> bool:
    return _ts is not None and _tst is not None


_LANG = {}


def _language(rel: str):
    key = "tsx" if rel.lower().endswith(".tsx") else "ts"
    if key not in _LANG:
        fn = _tst.language_tsx if key == "tsx" else _tst.language_typescript
        _LANG[key] = _ts.Language(fn())
    return _LANG[key]


# --- vocabulary specific to the JS side ------------------------------------
_HANDLER_METHODS = {"tool", "registerTool", "addTool", "setRequestHandler"}
# Decorators that REGISTER a class method as a tool handler (mcp-nest's @Tool).
_HANDLER_DECORATORS = {"Tool", "tool", "McpTool"}
_ENTRY_METHODS = {"connect", "listen"}
_NAME_NODES = ("identifier", "member_expression", "property_identifier")
_LOG_RECEIVER_RE = re.compile(r"(?i)(log|pino|winston|console)")
_LOG_METHODS_JS = {"log", "info", "warn", "error", "debug", "trace", "fatal"}
_APPEND_SINKS_JS = {"append", "appendFile", "appendFileSync", "record",
                    "writeRecord", "write_record", "appendRecord", "add_record",
                    "addRecord", "logEvent", "log_event", "writeEvent", "write_event"}
_DB_INSERT_JS = {"insert", "insertOne", "insertMany", "create"}
_SQL_EXEC_JS = {"query", "execute", "run"}
_OTEL_JS = {"startSpan", "startActiveSpan", "addEvent", "setAttribute",
            "recordException"}
# `Date.now()`, `new Date()`, `.toISOString()`, `performance.now()`
_TS_CALLS_JS = {"now", "toISOString", "getTime", "toUTCString"}
_TS_FIELDS_JS = _TS_FIELDS | {"at", "time", "createdat", "occurredat", "loggedat",
                              "recordedat", "eventtime", "timestampms"}
_TOOL_FIELDS_JS = _TOOL_FIELDS | {"toolname", "toolcalled", "toolinvoked"}
_HASH_JS = {"createHash", "createHmac", "sha256", "sha512", "subtle"}


def _text(n) -> str:
    return n.text.decode("utf-8", errors="replace")


def _walk(n):
    stack = [n]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def _callee(call) -> str:
    fn = call.child_by_field_name("function")
    return _text(fn) if fn is not None else ""


def _short(call) -> str:
    return _callee(call).split(".")[-1].split("?")[-1]


def _receiver(call) -> str:
    c = _callee(call)
    return c.rsplit(".", 1)[0] if "." in c else ""


def _args(call) -> list:
    a = call.child_by_field_name("arguments")
    return [c for c in a.children if c.is_named] if a is not None else []


def _idents(node) -> set:
    return {_text(c).lower() for c in _walk(node)
            if c.type in ("identifier", "property_identifier", "shorthand_property_identifier")}


def _string_words(node) -> set:
    out: set = set()
    for c in _walk(node):
        if c.type in ("string", "template_string"):
            out |= {w.lower() for w in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", _text(c))}
    return out


def _object_keys(node) -> set:
    """Keys of every object literal under `node`, lowercased, plus shorthand
    properties (`{ tool, ts }` names its fields as literally as `{ tool: t }`)."""
    keys: set = set()
    for c in _walk(node):
        if c.type == "pair":
            k = c.child_by_field_name("key")
            if k is not None:
                keys.add(_text(k).strip("'\"`").lower())
        elif c.type == "shorthand_property_identifier":
            keys.add(_text(c).lower())
    return keys


def _func_like(node) -> bool:
    return node.type in ("arrow_function", "function_expression", "function",
                         "function_declaration", "method_definition",
                         "generator_function_declaration")


def _tool_name_of(call) -> str | None:
    """The literal tool name when the registration carries one: the first
    string argument of tool()/registerTool(), or the `name:` key of addTool({})."""
    for a in _args(call):
        if a.type == "string":
            return _text(a).strip("'\"`")
        if a.type == "object":
            for c in a.children:
                if c.type == "pair" and _text(c.child_by_field_name("key")).strip("'\"") == "name":
                    v = c.child_by_field_name("value")
                    if v is not None and v.type == "string":
                        return _text(v).strip("'\"`")
    return None


def _unwrap(call) -> list:
    """Start nodes for a handler handed over WRAPPED: `withAudit(fn)`,
    `audit.wrap(fn)`, `this.add.bind(this)`. The wrapper's callee is a name to
    resolve (its body may hold the recorder) and every function-like or named
    argument is a body to walk. `.bind(this)` is not a wrapper: the thing
    being bound is the handler."""
    fn = call.child_by_field_name("function")
    out: list = []
    if fn is None:
        return out
    if fn.type == "member_expression" and _text(fn).split(".")[-1] == "bind":
        obj = fn.child_by_field_name("object")
        if obj is not None:
            out.append(obj)
        return out
    out.append(fn)
    for a in _args(call):
        if _func_like(a) or a.type in _NAME_NODES or a.type == "call_expression":
            out.append(a)
    return out


def _decorators_of(method) -> list:
    """Decorator nodes attached to a class member. tree-sitter puts them as
    preceding SIBLINGS in the class body, not as children of the method."""
    parent = method.parent
    if parent is None:
        return []
    decos, out = [], []
    for c in parent.children:
        if c.type == "decorator":
            decos.append(c)
        elif c == method:
            out = decos
            break
        elif c.is_named:
            decos = []
    return out


def _decorator_name(deco) -> str:
    for c in deco.children:
        if c.type == "call_expression":
            return _short(c)
        if c.type in _NAME_NODES:
            return _text(c).split(".")[-1]
    return ""


def _handler_roots(root) -> list:
    """(start nodes, tool name or None, line) for every tool handler. The start
    list holds the handler body plus any wrapper / decorator name whose body
    must be walked too; `_reachable` resolves the names."""
    out = []
    for n in _walk(root):
        if n.type == "method_definition":
            decos = _decorators_of(n)
            if not any(_decorator_name(d) in _HANDLER_DECORATORS for d in decos):
                continue
            starts = [n] + [c for d in decos for c in d.children
                            if c.type == "call_expression" or c.type in _NAME_NODES]
            name = None
            for d in decos:
                if _decorator_name(d) in _HANDLER_DECORATORS:
                    for c in d.children:
                        if c.type == "call_expression":
                            name = _tool_name_of(c)
            out.append((starts, name, n.start_point[0] + 1))
            continue
        if n.type != "call_expression" or _short(n) not in _HANDLER_METHODS:
            continue
        args = _args(n)
        if _short(n) == "setRequestHandler":
            # Only the tools/call handler answers this question. ListTools does not.
            if not args or "CallTool" not in _text(args[0]):
                continue
        starts: list = []
        for a in reversed(args):
            if _func_like(a):
                starts = [a]
                break
            if a.type == "object":  # addTool({ name, execute: async () => {} })
                for c in a.children:
                    if c.type == "pair" and _text(c.child_by_field_name("key")) in ("execute", "handler"):
                        v = c.child_by_field_name("value")
                        if v is not None and (_func_like(v) or v.type in _NAME_NODES
                                              or v.type == "call_expression"):
                            starts = [v]
                if starts:
                    break
            if a.type in _NAME_NODES:
                starts = [a]  # a named function passed by reference; resolved below
                break
            if a.type == "call_expression":
                starts = [a]  # withAudit(fn) / this.add.bind(this); unwrapped below
                break
        if starts:
            out.append((starts, _tool_name_of(n), n.start_point[0] + 1))
    return out


def _has_entrypoint(root) -> bool:
    for n in _walk(root):
        if n.type == "call_expression" and _short(n) in _ENTRY_METHODS:
            return True
        if n.type == "new_expression" and "Transport" in _text(n):
            return True
    return False


def _local_funcs(root) -> dict:
    """name -> function-like node, for declarations, `const f = () => {}`,
    class methods, `exports.f = () => {}`, and `const h = wrap(fn)` (a wrapped
    handler: the value is a call_expression that `_reachable` unwraps)."""
    funcs: dict = {}
    for n in _walk(root):
        if n.type in ("function_declaration", "generator_function_declaration"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                funcs[_text(nm)] = n
        elif n.type == "variable_declarator":
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and val is not None and (_func_like(val) or val.type == "call_expression"):
                funcs[_text(nm)] = val
        elif n.type == "method_definition":
            nm = n.child_by_field_name("name")
            if nm is not None:
                funcs[_text(nm)] = n
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and right is not None and left.type == "member_expression" and _func_like(right):
                funcs[_text(left).split(".")[-1]] = right
    return funcs


def _default_export(root):
    """The node behind `export default function f(){}` / `export default f`."""
    for n in _walk(root):
        if n.type != "export_statement" or not any(c.type == "default" for c in n.children):
            continue
        for c in n.children:
            if _func_like(c):
                return c
            if c.type == "identifier":
                return _local_funcs(root).get(_text(c))
    return None


_RELATIVE_IMPORT_RE = re.compile(r"^\.\.?/")


def _imports(root) -> list:
    """(local name, exported name, specifier) for every RELATIVE import.
    Exported name is "default" for a default import and "*" for a namespace
    import / bare require. Absolute and package imports are not returned: a
    resolver is only ever asked for a sibling of the graded file."""
    out = []
    for n in _walk(root):
        if n.type == "import_statement":
            src = n.child_by_field_name("source")
            spec = _text(src).strip("'\"") if src is not None else ""
            if not _RELATIVE_IMPORT_RE.match(spec):
                continue
            for clause in n.children:
                if clause.type != "import_clause":
                    continue
                for c in clause.children:
                    if c.type == "identifier":
                        out.append((_text(c), "default", spec))
                    elif c.type == "namespace_import":
                        for i in c.children:
                            if i.type == "identifier":
                                out.append((_text(i), "*", spec))
                    elif c.type == "named_imports":
                        for s in c.children:
                            if s.type != "import_specifier":
                                continue
                            names = [_text(i) for i in s.children if i.type == "identifier"]
                            if names:
                                out.append((names[-1], names[0], spec))
        elif n.type == "variable_declarator":
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if val is None or val.type != "call_expression" or _short(val) != "require":
                continue
            a = _args(val)
            spec = _text(a[0]).strip("'\"") if a and a[0].type == "string" else ""
            if not _RELATIVE_IMPORT_RE.match(spec) or nm is None:
                continue
            if nm.type == "identifier":
                out.append((_text(nm), "*", spec))
            elif nm.type == "object_pattern":
                for c in nm.children:
                    if c.type == "shorthand_property_identifier_pattern":
                        out.append((_text(c), _text(c), spec))
                    elif c.type == "pair_pattern":
                        k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
                        if k is not None and v is not None:
                            out.append((_text(v), _text(k), spec))
    return out


def _parse(source: str, rel: str):
    return _ts.Parser(_language(rel)).parse(source.encode("utf-8")).root_node


def _link_siblings(root, rel: str, local: dict, resolve,
                   unparsed: list | None = None) -> tuple[dict, list]:
    """Follow the graded file's relative imports through `resolve`. Returns
    (owner, sibling_roots): `owner` maps id(node) -> (specifier, that file's
    local function table) for every function the siblings define, and the
    graded file's `local` table gains entries for what it imported:
      named    `import { record }`      -> local["record"]
      default  `import audit from ...`  -> local["audit"] + local["audit.<f>"]
      namespace/require `* as ns`       -> local["ns.<f>"] for every sibling f
    Dotted keys are looked up by `_reachable` on the FULL callee text, so
    `ns.record()` finds the sibling and a bare `record()` does not."""
    owner: dict = {}
    sib_roots: list = []
    if resolve is None:
        return owner, sib_roots
    parsed: dict = {}
    for local_name, exported, spec in _imports(root):
        if spec not in parsed:
            src = resolve(spec)
            if not isinstance(src, str):
                parsed[spec] = None
                continue
            sib_rel = spec if spec.lower().endswith((".ts", ".tsx", ".js", ".mjs", ".cjs")) else spec + ".ts"
            try:
                sib_root = _parse(src, sib_rel)
                sib_local = _local_funcs(sib_root)
            except Exception:
                parsed[spec] = None
                if unparsed is not None and spec not in unparsed:
                    unparsed.append(spec)   # resolved, then would not parse
                continue
            parsed[spec] = (sib_root, sib_local)
            sib_roots.append((spec, sib_root))
            for fn in sib_local.values():
                owner[id(fn)] = (spec, sib_local)
        if parsed[spec] is None:
            continue
        sib_root, sib_local = parsed[spec]
        if exported == "default":
            d = _default_export(sib_root)
            if d is not None:
                local.setdefault(local_name, d)
                owner[id(d)] = (spec, sib_local)
            for name, fn in sib_local.items():
                local.setdefault("%s.%s" % (local_name, name), fn)
        elif exported == "*":
            for name, fn in sib_local.items():
                local.setdefault("%s.%s" % (local_name, name), fn)
        else:
            fn = sib_local.get(exported)
            if fn is not None:
                local.setdefault(local_name, fn)
    return owner, sib_roots


def _lookup(call, local: dict):
    """Callee -> known function node: the full dotted name first (`ns.record`,
    an imported namespace), then the bare short name (a local helper)."""
    full = _callee(call)
    return local.get(full) if full in local else local.get(_short(call))


def _reachable(starts: list, local: dict, owner: dict | None = None,
               max_depth: int = 2) -> list:
    """Function bodies reachable from `starts` within `max_depth` call hops.
    Names resolve through `local`; a body that came from a sibling file
    resolves ITS calls through that file's table (`owner`), so a helper called
    inside ./audit.ts is looked up in ./audit.ts. Wrapper calls unwrap for
    free (not a hop): the wrapper's body and the wrapped function are both
    starts. Returns (fn, origin) pairs; origin is None for the graded file."""
    owner = owner or {}
    seen, out, frontier = set(), [], [(s, 0) for s in starts]
    while frontier:
        fn, d = frontier.pop()
        if id(fn) in seen:
            continue
        seen.add(id(fn))
        if fn.type in _NAME_NODES:  # handler passed by name
            key = _text(fn)
            target = local.get(key) if key in local else local.get(key.split(".")[-1])
            if target is not None and id(target) not in seen:
                frontier.append((target, d))
            continue
        if fn.type == "call_expression":  # withAudit(fn) / this.add.bind(this)
            for s in _unwrap(fn):
                if id(s) not in seen:
                    frontier.append((s, d))
            continue
        if not _func_like(fn):
            continue
        origin, scope = owner.get(id(fn), (None, local))
        out.append((fn, origin))
        if d >= max_depth:
            continue
        for c in _walk(fn):
            if c.type == "call_expression":
                target = _lookup(c, scope)
                if target is not None and id(target) not in seen:
                    frontier.append((target, d + 1))
    return out


def _record_kind(call, tool_names: set) -> str:
    short, recv = _short(call), _receiver(call)
    if recv == "console" and short == "log":
        # console.log is stdout. It only becomes a record when it names the tool,
        # same rule as print()/logging in the Python check.
        pass
    if short in _LOG_METHODS_JS and recv and _LOG_RECEIVER_RE.search(recv):
        toks = _idents(call) | _string_words(call)
        if toks & _TOOL_FIELDS_JS or (toks & tool_names):
            return "logging call naming the tool"
        return ""
    if short in ("appendFile", "appendFileSync") or (
            short == "writeFile" and any("a" in _text(a) for a in _args(call) if a.type == "object")):
        return "append-mode file write"
    if short in _DB_INSERT_JS and recv:
        return "db %s()" % short
    if short in _SQL_EXEC_JS:
        for a in _args(call):
            if a.type in ("string", "template_string") and re.search(r"(?i)\binsert\b", _text(a)):
                return "db INSERT"
    if short in _OTEL_JS or recv in ("tracer", "span"):
        return "OpenTelemetry span"
    if short in _APPEND_SINKS_JS and recv and _LEDGERISH_RE.search(recv):
        return "ledger-style %s.%s()" % (recv, short)
    return ""


def _has_timestamp(fn, names: set) -> bool:
    if names & _TS_FIELDS_JS:
        return True
    for c in _walk(fn):
        if c.type == "call_expression" and _short(c) in _TS_CALLS_JS:
            return True
        if c.type == "new_expression" and _text(c).startswith("new Date"):
            return True
    return False


def _tamper_evidence(root):
    for n in _walk(root):
        if n.type in ("import_statement",):
            src = n.child_by_field_name("source")
            m = _text(src).strip("'\"") if src is not None else ""
            if _LEDGER_MODULE_RE.search(m):
                return ("ledger/append-only library %r" % m, n.start_point[0] + 1)
        if n.type == "call_expression" and _short(n) == "require":
            a = _args(n)
            if a and a[0].type == "string" and _LEDGER_MODULE_RE.search(_text(a[0])):
                return ("ledger/append-only library %s" % _text(a[0]), n.start_point[0] + 1)
    for n in _walk(root):
        if n.type == "pair":
            k = _text(n.child_by_field_name("key")).strip("'\"")
            if _CHAIN_FIELD_RE.search(k):
                return ("record field %r" % k, n.start_point[0] + 1)
        elif n.type == "variable_declarator":
            nm = n.child_by_field_name("name")
            if nm is not None and _CHAIN_FIELD_RE.search(_text(nm)):
                return ("chain variable %r" % _text(nm), n.start_point[0] + 1)
        elif n.type == "call_expression" and _short(n) == "createHmac":
            return ("hmac", n.start_point[0] + 1)
    for n in _walk(root):
        if _func_like(n):
            hashes = [c for c in _walk(n) if c.type == "call_expression" and _short(c) in _HASH_JS]
            if hashes and any(_LINK_NAME_RE.search(i) for i in _idents(n)):
                return ("hash chained to a previous record", hashes[0].start_point[0] + 1)
    return None


def _reconstructable(root):
    for n in _walk(root):
        if n.type in ("function_declaration", "method_definition"):
            nm = n.child_by_field_name("name")
            if nm is not None and _VERIFY_RE.match(_text(nm)):
                return ("%s()" % _text(nm), n.start_point[0] + 1)
        elif n.type == "variable_declarator":
            nm, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and val is not None and _func_like(val) and _VERIFY_RE.match(_text(nm)):
                return ("%s()" % _text(nm), n.start_point[0] + 1)
    for n in _walk(root):
        if n.type == "call_expression" and _VERIFY_RE.match(_short(n)):
            return ("call to %s()" % _short(n), n.start_point[0] + 1)
    return None


def audit_record_applies(source: str, rel: str = "x.ts") -> bool:
    """TS twin of checks.audit_record_applies: handlers AND an entrypoint, or
    the empty finding list means "not asked", not "clean"."""
    if not available():
        return False
    root = _ts.Parser(_language(rel)).parse(source.encode("utf-8")).root_node
    return bool(_handler_roots(root)) and _has_entrypoint(root)


def check_audit_record_ts(root, rel: str, resolve: Optional[Callable] = None) -> list[Finding]:
    """`resolve(spec) -> source | None` lets the walk follow the graded file's
    relative imports into sibling files (see module docstring). None = the
    file is graded alone, which is what a single-string grade can prove."""
    roots = _handler_roots(root)
    if not roots or not _has_entrypoint(root):
        return []
    tool_names = {t.lower() for _s, t, _l in roots if t}
    local = _local_funcs(root)
    owner, sib_roots = _link_siblings(root, rel, local, resolve)
    reached = _reachable([s for starts, _t, _l in roots for s in starts], local, owner)
    bodies = [fn for fn, _o in reached]

    writers: list = []
    for fn, origin in reached:
        calls, labels = [], []
        for c in _walk(fn):
            if c.type == "call_expression":
                kind = _record_kind(c, tool_names)
                if kind:
                    calls.append(c)
                    labels.append(kind if origin is None else "%s in %s" % (kind, origin))
        if calls:
            writers.append((fn, calls, labels, origin))

    presence = bool(writers)
    completeness, missing_fields = False, []
    # Fields are read across every reachable body, not just the one holding the
    # sink: `record(name, args)` assembles the record two hops above the
    # `appendFileSync` that stores it, and the record is no less complete for it.
    path_names: set = set()
    for fn in bodies:
        path_names |= _object_keys(fn) | _idents(fn)
    for fn, calls, _labels, _origin in writers:
        names = set(path_names)
        for call in calls:
            names |= _string_words(call)
        want = [("tool name", bool(names & _TOOL_FIELDS_JS)),
                ("timestamp", any(_has_timestamp(b, names) for b in bodies)),
                ("args/input digest", bool(names & _ARG_FIELDS))]
        if all(ok for _n, ok in want):
            completeness, missing_fields = True, []
            break
        if not missing_fields:
            missing_fields = [n for n, ok in want if not ok]

    # File-level gates read the graded file first, then the siblings it
    # imported: a chain and a verifier that live beside the recorder count.
    tamper = recon = None
    for _spec, r in [(None, root)] + sib_roots:
        tamper = tamper or _tamper_evidence(r)
        recon = recon or _reconstructable(r)
    gates = {"presence": presence, "completeness": completeness,
             "tamper_evidence": tamper is not None,
             "reconstructability": recon is not None}
    unmet = [(g, sev) for g, sev in _GATE_LADDER if not gates[g]]
    if not unmet:
        return []
    gate_name, severity = unmet[0]

    if presence:
        # `line` must point into the graded file: the first in-file sink if
        # there is one, else the handler whose walk crossed into a sibling.
        here = [c.start_point[0] + 1 for _f, cs, _l, o in writers if o is None for c in cs]
        first = min(here) if here else min(l for _s, _t, l in roots)
        seen_labels = sorted({l for _f, _c, ls, _o in writers for l in ls})
        wrote = "records a call at line %d (%s)" % (first, "; ".join(seen_labels))
    else:
        first = min(l for _s, _t, l in roots)
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


# --- except-returns-success (TS/JS front end) -------------------------------
#
# The TS twin of `checks.check_except_returns_success`. Same rule, same gate-2
# evidence (2026-09-04: the idiom scored 20 real of 57 opened, 35.1%, the only
# one of seven to clear its gate), same three exclusions.
#
# PARSER NOTE, because the brief that asked for this check assumed otherwise:
# the gate-2 SCRATCH harness read TypeScript with a comment-stripping,
# brace-matching regex pass, and its own limits section says so. THIS file does
# not. `ts_checks.py` has parsed TypeScript with tree-sitter since 0.0.17
# (module docstring: "What differs is the parser: tree-sitter instead of ast"),
# and adding a second, weaker front end beside it would mean two parsers
# disagreeing inside one module. So this check uses the tree-sitter node tree
# the file already builds. The regex pass's own confessed miss (a nested catch
# inside a template literal) does not apply here for the same reason.
#
# The real case this models is modelcontextprotocol/servers
# src/filesystem/index.ts:500: a `stat` failure inside `list_directory_with_sizes`
# is caught and reported as `{ size: 0, mtime: new Date(0) }`, listed beside the
# real entries and folded into the "Combined size" total. There is no error
# marker in the result; the only tell is the epoch date, and an agent adding up
# sizes will not notice it.
#
# One deliberate difference from the Python side: inline callbacks are NOT
# treated as a separate body. In Python a nested `def` inside a handler is rare
# and usually a different unit of work; in JavaScript the failing shape above
# lives inside an `entries.map(async (e) => { try {} catch {} })`, so a walk that
# stopped at the arrow would miss the very case the rule is named after.

_TS_ERROR_KEYS = {"error", "iserror", "errors"}
_TS_FALSE_KEYS = {"success", "ok"}
_TS_NULLISH = ("null", "undefined")
# Ported from scripts/vacuous_pass_lint.py the same way the Python check ports
# it; kept as its own tuple here so the TS front end has no import that only
# exists for prose.
_TS_POLARITY_WORDS = ("fail-open", "fail open", "fail-closed", "fail closed",
                      "refus", "don't block", "do not block", "never block",
                      "assume", "treat as", "deliberate", "on purpose",
                      "better to", "safe", "skip", "unavailable", "degraded")
_TS_POLARITY_MIN_CHARS = 60
_TS_POLARITY_NEAR = 2


def _pairs(obj) -> list:
    """(key, value) for the TOP-LEVEL pairs of an object literal. Top level on
    purpose: an `error` key nested three objects down is not this object's
    verdict about itself."""
    out = []
    for c in obj.children:
        if c.type != "pair":
            continue
        k, v = c.child_by_field_name("key"), c.child_by_field_name("value")
        if k is not None and v is not None:
            out.append((_text(k).strip("'\"`").lower(), v))
    return out


def _ts_error_marked(obj) -> bool:
    for key, value in _pairs(obj):
        flat = key.replace("_", "")
        if flat in _TS_ERROR_KEYS:
            return True
        if flat in _TS_FALSE_KEYS and value.type == "false":
            return True
    return False


def _ts_success_shape(node) -> str | None:
    """How an object/array literal returned from a catch reads to a caller that
    got no error, or None. A literal holding `null`/`undefined` is a modelled
    third state (supabase-mcp api-platform.ts:381 does exactly that) and is left
    alone."""
    if node is None:
        return None
    if node.type == "array":
        elts = [c for c in node.children if c.is_named]
        if any(e.type in _TS_NULLISH for e in elts):
            return None
        return "an empty array" if not elts else "an array literal"
    if node.type == "object":
        pairs = _pairs(node)
        if _ts_error_marked(node):
            return None
        if any(v.type in _TS_NULLISH for _k, v in pairs):
            return None
        return "{}" if not pairs else "an object literal"
    return None


def _ts_polarity_documented(catch, ret) -> bool:
    """A comment inside the catch clause, or within `_TS_POLARITY_NEAR` lines of
    the return, that says which way this fails. tree-sitter keeps comments as
    nodes, so this needs no second pass over the raw text."""
    blob, chars = [], 0
    for c in _walk(catch):
        if c.type != "comment":
            continue
        text = _text(c).lstrip("/*").rstrip("*/").strip()
        blob.append(text)
        chars += len(text)
    for c in _walk(ret):
        if c.type in ("string", "template_string"):
            blob.append(_text(c))
    low = " ".join(blob).lower()
    return any(w in low for w in _TS_POLARITY_WORDS) or chars >= _TS_POLARITY_MIN_CHARS


def _catch_param_names(catch) -> set:
    body = catch.child_by_field_name("body")
    return {_text(c) for c in catch.children
            if c.is_named and c is not body and c.type in ("identifier", "object_pattern")}


def _root_handler_name(starts: list, tool_name) -> str:
    """A name for a registered handler, for the `via` route: the tool name it
    was registered under when there is one, else the function's own name, else
    its shape."""
    if tool_name:
        return tool_name
    for s in starts:
        if _func_like(s):
            return _handler_label(s)
    return _text(starts[0]).strip() if starts else "a tool handler"


def _ts_catch_sites(root, rel: str, resolve: Optional[Callable] = None) -> dict:
    """{(file, line): [shape, where, via]} for every catch-returns-success SITE
    a registered tool handler reaches.

    Keyed by SITE, and the walk runs once PER HANDLER ROOT rather than once over
    every root together, because the route is part of the answer: a site reached
    from three handlers is one finding whose `via` names three, not three
    findings and not one finding that forgets the other two."""
    roots = _handler_roots(root)
    if not roots:
        return {}
    local = _local_funcs(root)
    owner, _sib_roots = _link_siblings(root, rel, local, resolve)
    # `resolve.resolved` (set by `file_resolver`) maps an import specifier to
    # the path it actually read, relative to the scan root. Without it the
    # specifier as written is the best honest name for the sibling; guessing an
    # extension would be a path that may not exist.
    resolved = getattr(resolve, "resolved", {}) if resolve is not None else {}

    sites: dict = {}
    for starts, tool_name, root_line in roots:
        via = [{"file": rel, "line": root_line,
                "handler": _root_handler_name(starts, tool_name)}]
        seen: set = set()
        for fn, origin in _reachable(list(starts), local, owner):
            for catch in _walk(fn):
                if catch.type != "catch_clause" or id(catch) in seen:
                    continue
                seen.add(id(catch))
                body = catch.child_by_field_name("body")
                if body is None:
                    continue
                if any(c.type == "throw_statement" for c in _walk(body)):
                    continue                  # rethrows: reported, not converted
                caught = _catch_param_names(catch)
                for ret in _walk(body):
                    if ret.type != "return_statement":
                        continue
                    value = next((c for c in ret.children if c.is_named
                                  and c.type != "comment"), None)
                    if value is None:
                        continue
                    if caught & {_text(i) for i in _walk(value)
                                 if i.type == "identifier"}:
                        continue              # hands back the caught error
                    shape = _ts_success_shape(value)
                    if shape is None:
                        continue
                    if _ts_polarity_documented(catch, ret):
                        continue
                    line = ret.start_point[0] + 1
                    label = _handler_label(fn)
                    if origin is None:
                        site_file, where = rel, "in %s" % label
                    else:
                        site_file = resolved.get(origin, origin)
                        where = "in %s at line %d of %s" % (label, line, origin)
                    key = (site_file, line)
                    if key in sites:
                        _merge_via(sites[key][2], via)
                    else:
                        sites[key] = [shape, where, list(via)]
    return sites


def ts_check_catch_returns_success(root, rel: str,
                                   resolve: Optional[Callable] = None) -> list[Finding]:
    """A `catch` block inside a registered tool handler that returns an object
    or array literal carrying no `isError` / `error` key: the failure is
    serialised into the tool result and the agent reads it as an answer.

    Tree-sitter, not a regex and not brace matching (see the block comment
    above). `resolve(spec) -> source | None` follows relative imports into
    sibling files exactly as `check_audit_record_ts` does.

    WHERE IT POINTS (changed 2026-09-04, the twin of the Python change):
    `file`/`line` are the CATCH SITE: the file the catch lives in and the line
    of the `return` inside it. The registered tool handler that reaches it
    travels in `via` as `{"file", "line", "handler"}`. A finding whose site was
    in a sibling used to be reported at the graded file's first handler line,
    which pointed a reader at code with no `catch` in it."""
    out: list[Finding] = []
    for (site_file, line), (shape, where, via) in _ts_catch_sites(root, rel, resolve).items():
        out.append(Finding(
            "except-returns-success", "medium", site_file, line,
            "catch block returns %s with no isError/error key, %s, on a path a "
            "tool handler reaches (%s): the failure is handed back as a "
            "successful result and the caller cannot tell it apart from a real "
            "answer" % (shape, where, _via_phrase(via)),
            None, via or None))
    return out


def _handler_label(fn) -> str:
    """A name for the body a finding sits in: the declared name when there is
    one, else the shape (an inline arrow has no name to print)."""
    nm = fn.child_by_field_name("name")
    if nm is not None:
        return "%s()" % _text(nm)
    return "an inline handler" if fn.type == "arrow_function" else fn.type


def ts_except_success_coverage(source: str, rel: str = "<source>",
                               resolve: Optional[Callable] = None) -> dict:
    """What the TS front end actually looked at, the twin of
    `checks.except_success_coverage`.

    Added 2026-09-04. Until then the coverage line was Python-only, and the
    measured cost was exact: supabase-mcp's `packages/` reported zero findings
    off 24 registered handlers, 29 walked bodies and ZERO catch clauses reached
    (its catch blocks live in a platform layer no handler walk enters). A zero
    with no counts beside it cannot say whether it means "nothing to find" or
    "nothing looked at", which is the same third verdict this check is about,
    and the front end that produced the tool's only real hit on that population
    was the one that could not say it."""
    cov = {"handler_roots": 0, "bodies_examined": 0,
           "catch_clauses_examined": 0, "files_unparsed": 0,
           "sites_reported": 0, "handlers_reaching": 0}
    if not available():
        cov["files_unparsed"] = 1        # not scanned; never report it as clean
        return cov
    root = _ts.Parser(_language(rel)).parse(source.encode("utf-8")).root_node
    if root.has_error and not any(c.type != "ERROR" for c in root.children):
        cov["files_unparsed"] = 1
        return cov
    roots = _handler_roots(root)
    cov["handler_roots"] = len(roots)
    if not roots:
        return cov
    local = _local_funcs(root)
    unparsed: list = []
    owner, _sib_roots = _link_siblings(root, rel, local, resolve, unparsed)
    cov["files_unparsed"] = len(unparsed)
    reached = _reachable([s for starts, _t, _l in roots for s in starts], local, owner)
    cov["bodies_examined"] = len(reached)
    seen: set = set()
    for fn, _origin in reached:
        for c in _walk(fn):
            if c.type == "catch_clause" and id(c) not in seen:
                seen.add(id(c))
                cov["catch_clauses_examined"] += 1
    # The dedup, said out loud: findings are one per catch SITE, and a site
    # several handlers reach carries several `via` entries instead of becoming
    # several findings. Computed from the check itself so the summary line can
    # never disagree with the findings it summarises.
    sites = _ts_catch_sites(root, rel, resolve)
    cov["sites_reported"] = len(sites)
    cov["handlers_reaching"] = len({(v["file"], v["line"])
                                    for _s, _w, via in sites.values() for v in via})
    return cov


TS_CHECKS = [("audit-record", check_audit_record_ts),
             ("except-returns-success", ts_check_catch_returns_success)]


def is_ts_path(rel: str) -> bool:
    return rel.lower().endswith((".ts", ".tsx", ".js", ".mjs", ".cjs"))


_SIBLING_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")


def file_resolver(base_dir: str | Path, root: str | Path | None = None) -> Callable:
    """A `resolve(spec)` for `scan_source_ts_ex` that reads sibling files from
    disk. `spec` is the import specifier as written (`./audit`, `./audit.js`,
    `../lib/audit`); TS convention lets `./audit.js` name `audit.ts`, so the
    stated suffix is tried first, then each source suffix, then an index file.
    Files outside `root` (when given) are never read: the scan's scope is the
    tree it was pointed at, and a path that climbs out of it is not part of
    the grade.

    The returned callable carries a `resolved` dict: import specifier -> the
    path it actually read, relative to `root`, forward slashes. A finding whose
    site is in a sibling reports THAT path as its `file`, and only the resolver
    knows which of `./audit`, `./audit.ts` and `./audit/index.ts` it opened;
    without the map a caller would have to guess an extension and could name a
    file that does not exist."""
    base = Path(base_dir)
    top = Path(root).resolve() if root is not None else None

    def resolve(spec: str):
        raw = base / spec
        stem = raw
        if raw.suffix.lower() in _SIBLING_SUFFIXES:
            stem = raw.with_suffix("")
        candidates = [raw] + [stem.with_name(stem.name + s) for s in _SIBLING_SUFFIXES] \
            + [stem / ("index" + s) for s in _SIBLING_SUFFIXES]
        for cand in candidates:
            try:
                if not cand.is_file():
                    continue
                real = cand.resolve()
                if top is not None and top not in real.parents:
                    return None
                if top is not None:
                    try:
                        resolve.resolved[spec] = str(
                            real.relative_to(top)).replace("\\", "/")
                    except ValueError:
                        pass
                else:
                    resolve.resolved[spec] = cand.name
                return cand.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        return None

    resolve.resolved = {}
    return resolve


def scan_source_ts_ex(source: str, rel: str,
                      resolve: Optional[Callable] = None) -> tuple[list[Finding], list[str]]:
    """(findings, checks that ACTUALLY ran). Without the [ts] extra nothing
    runs and the second element is [] -- a grade must read that, never assume.
    `resolve` (optional) follows relative imports into sibling files; see
    `file_resolver` and the module docstring."""
    if not available():
        return [Finding("parse", "info", rel, 0,
                        "TypeScript front end unavailable: pip install 'arcaeon[ts]'")], []
    parser = _ts.Parser(_language(rel))
    tree = parser.parse(source.encode("utf-8"))
    root = tree.root_node
    if root.has_error and not any(c.type != "ERROR" for c in root.children):
        return [Finding("parse", "info", rel, 0, "could not parse")], []
    out, ran = [], []
    for name, check in TS_CHECKS:
        out.extend(check(root, rel, resolve))
        ran.append(name)
    return out, ran
