"""Dynamic checks: questions that can only be answered by CALLING a live tool.

Added 2026-09-05. Every check in `checks.py` is a pure function over parsed
source; none of them can say whether a declared filter parameter is actually
wired to anything. A forum correspondent showed the gap live the night before:
`user_id=` (an unknown key) silently returned the whole corpus, `author_id=` set
to a malformed value 422'd. Validation and application ship independently, so a
count quoted from such an endpoint is unfalsifiable from the outside. The only
way to know is to call the tool twice and diff the cardinality. Research note:
`projects/online_business/build_idea_param_binding_liveness_2026-09-05.md`.

This module holds the registry and the check logic. It imports NO SDK: the
check talks to the server through a small duck-typed `session` object that
`probe.py` supplies, so `dynamic_check_names()` works in an install that never
took the [mcp] extra, and so the logic is testable without a subprocess.

Findings reuse the static `Finding` dataclass so one consumer parses both. The
site convention differs, and is stated in the artifact: `file` carries the TOOL
NAME (the thing a reader opens) and `line` is 0, because a live probe has no
source line to point at.
"""
from __future__ import annotations

import re
import secrets

from .checks import Finding

# --- the dynamic registry ---------------------------------------------------
# Same shape and same reason as `checks.CHECKS`: the probe artifact's
# `dynamic_checks_run` is read off this list, so it cannot claim a check the
# code did not execute. Adding a check = one decorated function.

DYNAMIC_CHECKS: list = []


def register_dynamic(name: str):
    """Register a dynamic check under the `check` name its findings carry.
    Signature: `check_fn(session, tool) -> list[Finding]`, where `session` is
    the probe harness (see `probe.ProbeSession`) and `tool` is the SDK's
    `Tool` (name, description, input_schema, annotations)."""
    def deco(fn):
        DYNAMIC_CHECKS.append((name, fn))
        return fn
    return deco


def dynamic_check_names() -> list:
    """The dynamic check classes that actually run, in run order."""
    return [name for name, _ in DYNAMIC_CHECKS]


# --- sub-verdicts ------------------------------------------------------------
# Two verdicts, one check. The severity ladder here is the static one
# (high / medium / low / info); the research note asked for "medium-high" on
# the first, which the ladder has no rung for. It rounds UP: a filter that
# does not filter means the tool's declared contract is false, and every count
# an agent quotes through it is wrong in the understating direction.
DOES_NOT_BIND = "declared parameter does not bind"
DOES_NOT_BIND_SEVERITY = "high"
UNKNOWN_ACCEPTED = "unknown parameter silently accepted"
UNKNOWN_ACCEPTED_SEVERITY = "medium"

# Impossible-but-well-formed values. A random 24-char hex token cannot collide
# with a real id/author/status by accident; the integer is well outside any
# plausible id or page size and negative so a `limit` cannot mean "that many".
IMPOSSIBLE_INT = -987654321
UNKNOWN_KEY_PREFIX = "mcp_vet_unknown_probe_"

_FILTER_WORDS = (
    "id", "filter", "author", "user", "owner", "status", "type", "category",
    "since", "before", "after", "limit",
)
_SCALAR_TYPES = ("string", "integer", "number")


def impossible_string() -> str:
    return secrets.token_hex(12)          # 24 chars


def unknown_key() -> str:
    return UNKNOWN_KEY_PREFIX + secrets.token_hex(4)


def _scalar_type(prop: dict) -> str | None:
    """The scalar JSON type of a property, unwrapping the `anyOf: [T, null]`
    and `type: [T, "null"]` spellings an optional parameter arrives in. None
    for booleans, arrays, objects, refs, and anything with more than one
    non-null type: an impossible value only means something for one type."""
    if not isinstance(prop, dict):
        return None
    t = prop.get("type")
    if isinstance(t, list):
        non_null = [x for x in t if x != "null"]
        t = non_null[0] if len(non_null) == 1 else None
    if t is None:
        alts = prop.get("anyOf") or prop.get("oneOf") or []
        non_null = [a for a in alts if isinstance(a, dict) and a.get("type") != "null"]
        if len(non_null) == 1:
            return _scalar_type(non_null[0])
        return None
    return t if t in _SCALAR_TYPES else None


def _mentions_filter_word(text: str) -> bool:
    # Whole-token match on word boundaries, so "author_id" and "userId" hit
    # (split on `_` and case changes) while "valid" and "width" do not hit
    # on "id" / "since".
    tokens = re.findall(r"[A-Za-z]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", text))
    return any(tok.lower() in _FILTER_WORDS for tok in tokens)


def filter_shaped_params(schema: dict) -> list[tuple[str, str]]:
    """The parameters worth probing, as (name, scalar type) in schema order.

    ONE named heuristic, kept here so it can be tested and argued with. A
    property is filter-shaped when it is scalar (string / integer / number,
    optionally nullable) AND either its name or description carries a
    filtering word (id, filter, author, user, owner, status, type, category,
    since, before, after, limit) OR it is optional. Required scalars with no
    such word (a search `query`, a `path`) are left alone: an impossible
    value there tests input validation, not binding."""
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties") or {}
    required = set(schema.get("required") or [])
    out = []
    for name, prop in props.items():
        t = _scalar_type(prop)
        if t is None:
            continue
        desc = prop.get("description", "") if isinstance(prop, dict) else ""
        if _mentions_filter_word(name) or _mentions_filter_word(desc) \
                or name not in required:
            out.append((name, t))
    return out


def neutral_args(schema: dict) -> dict:
    """Arguments for the control call: required properties only, each filled
    with the blandest value of its type. Optional properties are left OUT,
    because the control is "no filter applied"."""
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties") or {}
    args = {}
    for name in schema.get("required") or []:
        prop = props.get(name, {})
        t = _scalar_type(prop) or (prop.get("type") if isinstance(prop, dict) else None)
        if t == "string":
            args[name] = ""
        elif t in ("integer", "number"):
            args[name] = 1
        elif t == "boolean":
            args[name] = False
        elif t == "array":
            args[name] = []
        else:
            args[name] = {}
    return args


def impossible_value(scalar_type: str):
    return impossible_string() if scalar_type == "string" else IMPOSSIBLE_INT


# --- cardinality -------------------------------------------------------------

_LIST_KEYS = ("result", "results", "items", "data", "rows", "records")


def cardinality(structured, content: list) -> int | None:
    """How many items a successful tool result carries, or None when the
    result has no countable shape.

    Prefers `structuredContent`: a list is counted directly; a dict whose
    single value is a list (the Python SDK wraps a list return as
    `{"result": [...]}`) or that carries one under a conventional key is
    counted through that list; any other dict is one object. Falls back to
    the content blocks: the SDK emits one text block per list item, and a
    single text block that parses as a JSON list is counted through it."""
    if isinstance(structured, list):
        return len(structured)
    if isinstance(structured, dict):
        if len(structured) == 1:
            (only,) = structured.values()
            if isinstance(only, list):
                return len(only)
        for k in _LIST_KEYS:
            if isinstance(structured.get(k), list):
                return len(structured[k])
        return 1
    if not content:
        return 0
    if len(content) > 1:
        return len(content)
    text = getattr(content[0], "text", None)
    if isinstance(text, str):
        import json
        try:
            parsed = json.loads(text)
        except ValueError:
            return 1
        if isinstance(parsed, (list, dict)):
            return cardinality(parsed, [])
    return 1


# --- param-binding-liveness --------------------------------------------------

def _is_read_only(tool) -> bool:
    ann = getattr(tool, "annotations", None)
    return bool(ann is not None and getattr(ann, "read_only_hint", None) is True)


@register_dynamic("param-binding-liveness")
def param_binding_liveness(session, tool) -> list[Finding]:
    """Call the tool with an impossible filter value and with an unknown key,
    and compare each against a control call.

    Skips, each recorded as a blind spot on the session, never as a finding
    and never as a pass:
      - not annotated `readOnlyHint: true` (absent or false = assume it
        writes; two garbage calls could double-create or double-charge);
      - the control call errored (auth, validation, timeout: nothing to
        compare against);
      - the control returned 0 or 1 items (a `get_by_id` tool legitimately
        returns one row whether or not filtering works).

    An impossible value that the server REJECTS (error result) is neither a
    finding nor a blind spot: that is validation doing its job, and the
    question this check asks is about the other case."""
    name = tool.name
    schema = getattr(tool, "input_schema", None) or {}
    if not _is_read_only(tool):
        session.blind_spot(name, "skipped: not annotated readOnlyHint=true "
                                 "(absent or false is treated as write-capable)")
        return []

    control_args = neutral_args(schema)
    control = session.call(name, control_args)
    if control.error is not None:
        session.blind_spot(name, "skipped: control call failed: %s" % control.error)
        return []
    baseline = control.cardinality
    if baseline is None or baseline <= 1:
        session.blind_spot(name, "skipped: naturally singular / no baseline "
                                 "cardinality (control call returned %s)"
                                 % ("uncountable" if baseline is None else baseline))
        return []

    findings: list[Finding] = []

    # Unknown key first: one call, independent of the schema's parameters.
    key = unknown_key()
    r = session.call(name, {**control_args, key: "x"})
    if r.error is None:
        findings.append(Finding(
            check="param-binding-liveness", severity=UNKNOWN_ACCEPTED_SEVERITY,
            file=name, line=0,
            detail="%s: extra key %r was accepted with a success result "
                   "(%s item(s), control %s); the server does not reject "
                   "keys outside inputSchema.properties"
                   % (UNKNOWN_ACCEPTED, key,
                      "uncountable" if r.cardinality is None else r.cardinality,
                      baseline),
        ))

    for pname, ptype in filter_shaped_params(schema):
        value = impossible_value(ptype)
        r = session.call(name, {**control_args, pname: value})
        if r.error is not None or r.cardinality is None:
            continue
        if r.cardinality >= baseline:
            findings.append(Finding(
                check="param-binding-liveness", severity=DOES_NOT_BIND_SEVERITY,
                file=name, line=0,
                detail="%s: %s=%r returned %d item(s), control returned %d; "
                       "an impossible value did not reduce the result"
                       % (DOES_NOT_BIND, pname, value, r.cardinality, baseline),
            ))
    return findings
