"""Unit tests for mcp_vet.dynamic_checks (2026-09-05): the registry, the
filter-shape heuristic, cardinality, and the param-binding-liveness check
driven through a FAKE session. No SDK, no subprocess; the live end of the
same check is proven in test_probe.py against a real stdio server.

Two of these are PLANTED RED: a fake server that ignores every argument, and
one that swallows unknown keys. If the check ever started skipping silently
(a refactor that returns [] before the calls, say) those two go red while
every "yields nothing" test would stay green. That asymmetry is the point.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arcaeon.prove.vet import dynamic_checks as dc  # noqa: E402
from arcaeon.prove.vet.checks import Finding  # noqa: E402
from arcaeon.prove.vet.dynamic_checks import (  # noqa: E402
    DOES_NOT_BIND, DYNAMIC_CHECKS, IMPOSSIBLE_INT, UNKNOWN_ACCEPTED,
    UNKNOWN_KEY_PREFIX, cardinality, dynamic_check_names, filter_shaped_params,
    neutral_args, param_binding_liveness,
)


# --- fakes -------------------------------------------------------------------

def _tool(name="list_things", props=None, required=(), read_only=True, annotations=True):
    schema = {"type": "object", "properties": props or {}, "required": list(required)}
    ann = SimpleNamespace(read_only_hint=read_only) if annotations else None
    return SimpleNamespace(name=name, description="", input_schema=schema, annotations=ann)


class FakeSession:
    """Answers each call from `behave(name, args) -> (error, cardinality)` and
    records everything, the way ProbeSession does."""
    def __init__(self, behave):
        self.behave = behave
        self.calls = []
        self.blind_spots = []

    def call(self, name, args):
        self.calls.append((name, dict(args)))
        err, card = self.behave(name, args)
        return SimpleNamespace(error=err, cardinality=card)

    def blind_spot(self, tool, reason):
        self.blind_spots.append({"tool": tool, "reason": reason})


def _is_unknown_key(k):
    return k.startswith(UNKNOWN_KEY_PREFIX)


def honest_server(rows=10):
    """Filters really filter, unknown keys are rejected."""
    def behave(name, args):
        if any(_is_unknown_key(k) for k in args):
            return "unknown argument", None
        if any(v == IMPOSSIBLE_INT or (isinstance(v, str) and len(v) == 24) for v in args.values()):
            return None, 0
        return None, rows
    return behave


def ignoring_server(rows=10):
    """Every argument is ignored; every key is accepted."""
    return lambda name, args: (None, rows)


# --- registry ----------------------------------------------------------------

def test_registry_names_come_from_the_live_list():
    assert dynamic_check_names() == [n for n, _ in DYNAMIC_CHECKS]
    assert "param-binding-liveness" in dynamic_check_names()
    assert all(callable(fn) for _, fn in DYNAMIC_CHECKS)


def test_registry_is_separate_from_the_static_one():
    from arcaeon.prove.vet.checks import check_names
    assert not set(dynamic_check_names()) & set(check_names())


# --- the heuristic -----------------------------------------------------------

def test_filter_shaped_by_name_word():
    props = {"author_id": {"type": "string"}, "userId": {"type": "string"},
             "status": {"type": "string"}, "limit": {"type": "integer"},
             "since": {"type": "number"}}
    got = filter_shaped_params({"properties": props, "required": list(props)})
    assert got == [("author_id", "string"), ("userId", "string"), ("status", "string"),
                   ("limit", "integer"), ("since", "number")]


def test_filter_shaped_by_description_word():
    props = {"q": {"type": "string", "description": "restrict to this owner"}}
    assert filter_shaped_params({"properties": props, "required": ["q"]}) == [("q", "string")]


def test_optional_scalar_is_filter_shaped_without_a_word():
    props = {"page_size": {"type": "integer"}}
    assert filter_shaped_params({"properties": props}) == [("page_size", "integer")]


def test_required_scalar_without_a_word_is_not_filter_shaped():
    props = {"query": {"type": "string"}, "width": {"type": "integer"}}
    assert filter_shaped_params({"properties": props, "required": ["query", "width"]}) == []


def test_substring_false_friends_do_not_match():
    # "width" contains "id", "valid" contains "id", "evidence" contains "id":
    # whole-token matching only.
    props = {"width": {"type": "integer"}, "valid": {"type": "string"},
             "evidence": {"type": "string"}}
    assert filter_shaped_params({"properties": props, "required": list(props)}) == []


def test_nullable_spellings_unwrap():
    props = {"author_id": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
             "user_id": {"type": ["string", "null"]},
             "owner": {"oneOf": [{"type": "integer"}, {"type": "null"}]}}
    assert filter_shaped_params({"properties": props}) == [
        ("author_id", "string"), ("user_id", "string"), ("owner", "integer")]


def test_non_scalars_are_never_filter_shaped():
    props = {"active": {"type": "boolean"}, "ids": {"type": "array"},
             "filter": {"type": "object"}, "ref": {"$ref": "#/defs/X"},
             "either": {"anyOf": [{"type": "string"}, {"type": "integer"}]}}
    assert filter_shaped_params({"properties": props}) == []


def test_heuristic_tolerates_garbage_schema():
    assert filter_shaped_params(None) == []
    assert filter_shaped_params({}) == []
    assert filter_shaped_params({"properties": {"x": "not-a-dict"}}) == []


def test_neutral_args_fill_required_only():
    schema = {"properties": {"q": {"type": "string"}, "n": {"type": "integer"},
                             "flag": {"type": "boolean"}, "tags": {"type": "array"},
                             "opt": {"type": "string"}},
              "required": ["q", "n", "flag", "tags"]}
    assert neutral_args(schema) == {"q": "", "n": 1, "flag": False, "tags": []}
    assert neutral_args({}) == {} and neutral_args(None) == {}


# --- cardinality -------------------------------------------------------------

def _text(s):
    return SimpleNamespace(type="text", text=s)


@pytest.mark.parametrize("structured,content,expected", [
    ([1, 2, 3], [], 3),
    ({"result": [1, 2]}, [], 2),                      # SDK's list-return wrap
    ({"items": [1, 2, 3, 4], "total": 4}, [], 4),     # conventional key
    ({"id": 1, "title": "x"}, [], 1),                 # one object
    ({"result": []}, [], 0),
    (None, [_text("a"), _text("b"), _text("c")], 3),  # one block per item
    (None, [_text('[1, 2, 3, 4, 5]')], 5),            # one block, JSON list
    (None, [_text('{"data": [1, 2]}')], 2),
    (None, [_text("just prose")], 1),
    (None, [], 0),
])
def test_cardinality(structured, content, expected):
    assert cardinality(structured, content) == expected


# --- the check, through a fake session ---------------------------------------

def test_not_read_only_is_a_blind_spot_and_zero_calls():
    for tool in (_tool(read_only=False), _tool(read_only=None),
                 _tool(annotations=False)):
        s = FakeSession(ignoring_server())
        assert param_binding_liveness(s, tool) == []
        assert s.calls == []
        assert len(s.blind_spots) == 1 and "readOnlyHint" in s.blind_spots[0]["reason"]


def test_control_failure_is_a_blind_spot_not_a_finding():
    s = FakeSession(lambda n, a: ("401 unauthorized", None))
    tool = _tool(props={"author_id": {"type": "string"}})
    assert param_binding_liveness(s, tool) == []
    assert len(s.calls) == 1
    assert "control call failed" in s.blind_spots[0]["reason"]
    assert "401" in s.blind_spots[0]["reason"]


@pytest.mark.parametrize("baseline", [0, 1, None])
def test_singular_baseline_is_a_blind_spot(baseline):
    s = FakeSession(lambda n, a: (None, baseline))
    tool = _tool(props={"author_id": {"type": "string"}})
    assert param_binding_liveness(s, tool) == []
    assert len(s.calls) == 1, "nothing beyond the control call may be spent"
    assert "naturally singular" in s.blind_spots[0]["reason"]


def test_honest_server_yields_nothing():
    s = FakeSession(honest_server())
    tool = _tool(props={"author_id": {"type": "string"}, "limit": {"type": "integer"}})
    assert param_binding_liveness(s, tool) == []
    assert s.blind_spots == []
    # control + unknown key + one per filter-shaped param
    assert len(s.calls) == 4


def test_PLANTED_RED_ignoring_server_draws_does_not_bind():
    """PLANTED RED: a server that ignores `author_id` MUST draw the
    does-not-bind verdict. Goes red if the check silently skips."""
    s = FakeSession(ignoring_server())
    tool = _tool(props={"author_id": {"type": "string"}})
    fs = param_binding_liveness(s, tool)
    dnb = [f for f in fs if DOES_NOT_BIND in f.detail]
    assert len(dnb) == 1, fs
    assert dnb[0].severity == "high" and dnb[0].check == "param-binding-liveness"
    assert dnb[0].file == "list_things" and dnb[0].line == 0
    assert "author_id=" in dnb[0].detail and "control returned 10" in dnb[0].detail


def test_PLANTED_RED_unknown_key_swallowed_draws_unknown_accepted():
    """PLANTED RED: a server that accepts a key outside inputSchema MUST draw
    the unknown-accepted verdict, even when its declared filters work."""
    def behave(name, args):
        if any(v == IMPOSSIBLE_INT or (isinstance(v, str) and len(v) == 24)
               for k, v in args.items() if not _is_unknown_key(k)):
            return None, 0
        return None, 10
    s = FakeSession(behave)
    tool = _tool(props={"author_id": {"type": "string"}})
    fs = param_binding_liveness(s, tool)
    assert [UNKNOWN_ACCEPTED in f.detail for f in fs] == [True], fs
    assert fs[0].severity == "medium"
    sent = [k for _, a in s.calls for k in a if _is_unknown_key(k)]
    assert len(sent) == 1 and sent[0] in fs[0].detail


def test_both_verdicts_together_on_one_tool():
    s = FakeSession(ignoring_server())
    tool = _tool(props={"user_id": {"type": "string"}})
    fs = param_binding_liveness(s, tool)
    assert sorted(f.severity for f in fs) == ["high", "medium"]
    assert {f.detail.split(":")[0] for f in fs} == {DOES_NOT_BIND, UNKNOWN_ACCEPTED}


def test_rejected_impossible_value_is_neither_finding_nor_blind_spot():
    """A 422 on the impossible value is validation working; the question
    this check asks is about the other case."""
    def behave(name, args):
        if any(_is_unknown_key(k) for k in args):
            return "unknown argument", None
        if args:
            return "422 invalid author_id", None
        return None, 10
    s = FakeSession(behave)
    tool = _tool(props={"author_id": {"type": "string"}})
    assert param_binding_liveness(s, tool) == []
    assert s.blind_spots == []


def test_impossible_values_are_sent_per_type_and_required_args_kept():
    s = FakeSession(honest_server())
    tool = _tool(props={"q": {"type": "string"}, "owner": {"type": "string"},
                        "limit": {"type": "integer"}},
                 required=["q", "owner"])
    param_binding_liveness(s, tool)
    control = s.calls[0][1]
    assert control == {"q": "", "owner": ""}
    by_param = {next(k for k in a if k not in control or a[k] != control[k]): a
                for _, a in s.calls[1:]}
    owner_probe = next(a for k, a in by_param.items() if k == "owner")
    assert isinstance(owner_probe["owner"], str) and len(owner_probe["owner"]) == 24
    assert owner_probe["q"] == "", "required args ride along on every probe"
    limit_probe = next(a for k, a in by_param.items() if k == "limit")
    assert limit_probe["limit"] == IMPOSSIBLE_INT


def test_findings_are_the_static_finding_shape():
    s = FakeSession(ignoring_server())
    fs = param_binding_liveness(s, _tool(props={"user_id": {"type": "string"}}))
    for f in fs:
        assert isinstance(f, Finding)
        d = f.as_dict()
        assert set(d) == {"check", "severity", "file", "line", "detail"}


def test_cap_exception_from_session_propagates():
    class Cap(Exception):
        pass

    def behave(name, args):
        raise Cap()
    s = FakeSession(behave)
    with pytest.raises(Cap):
        param_binding_liveness(s, _tool(props={"user_id": {"type": "string"}}))


def test_module_does_not_import_the_sdk():
    """dynamic_check_names() must work in an install that never took [mcp]:
    the artifact reads the registry, and the registry must not need the SDK.
    Checked on the source rather than by reloading under a stubbed
    sys.modules, because a reload would hand `probe.py` a stale registry."""
    import re
    src = Path(dc.__file__).read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+mcp\b", src, re.M), \
        "dynamic_checks.py must stay SDK-free"
