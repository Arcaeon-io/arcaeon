# SPDX-License-Identifier: MIT
"""arcaeon.connect.mcp_result: verify a sealed MCP tool result before the model reads it.

    from arcaeon.connect.mcp_result import verify_tool_result, GatewayConfig
    cfg = GatewayConfig.from_dict({"audience": "agent-1", "signers": ["did:key:z6Mk..."]})
    new_result, decision = verify_tool_result(call_tool_result, action="read", config=cfg)

The one check both gateway kits run (docs/GATEWAYS.md): the Lasso mcp-gateway
plugin (arcaeon.connect.lasso, L4-02) and the Docker MCP Gateway after-
interceptor (arcaeon.connect.docker_after, L4-03). Nothing here checks a byte
itself: the bundle and the bytes it seals are written to a temp dir and handed
to arcaeon.prove.gate.decide (record=False), which hands them to
arcaeon.prove.envelope.verify, the one verifier. Same pattern as the A2A
receiver.

WHERE THE BUNDLE RIDES (MCP 2026-07-28 `_meta`, a vendor prefix of our own):

    content[i]._meta["dev.arcaeon/bundle"]   seals that content block's bytes
    result._meta["dev.arcaeon/bundle"]       seals the one content block, when
                                             the result has exactly one

The value is the envelope object `arcaeon envelope seal` writes as
FILE.envelope.json (or that object as a JSON string). The bytes a block
offers: text -> its text as UTF-8; image / audio -> base64-decoded `data`;
embedded resource -> `resource.text` as UTF-8 or base64-decoded
`resource.blob`. A resource_link carries no bytes: COULD NOT LOOK.

WHAT COUNTS AS COVERED. Every content block must be sealed and every seal must
hold, and `structuredContent`, when present, must be the same JSON as one
sealed text block (the spec's own back-compat rule: a tool that returns
structured content SHOULD also return it serialized in a text block). Anything
the model would read that no seal covers is COULD NOT LOOK. No bundle at all
is COULD NOT LOOK. BROKEN anywhere wins over COULD NOT LOOK.

THE RULE AND THE MODE are the gate's: VERIFIED allows every action; COULD NOT
LOOK allows read only; BROKEN allows nothing; act, pay and irreversible also
need the exchange named (deal and purpose). The mode is
arcaeon.prove.gate_mode: the config's `enforce`, else ARCAEON_GATE_MODE, else
the cached signed latest.json block_after, else block.

    allowed          the result passes through unchanged but for
                     _meta["dev.arcaeon/verdict"]
    refused, block   the result is REPLACED by {content: [one text block
                     saying REFUSED, the word and why], isError: true}; the
                     tool's own content never reaches the model
    refused, warn    the result passes through, the verdict in _meta carries
                     `warning` ("would refuse in block mode")

WHICH ACTION a tool result stands for is the receiver's call, never the
sender's: per tool in the config (`tools`), else `default_action`, default
"act" (fail closed: an unlisted tool's output is held to the act rule).
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G
from arcaeon.prove import gate_mode as GM
from arcaeon.record.row import loads_strict

__all__ = ["BUNDLE_KEY", "VERDICT_KEY", "DEFAULT_ACTION", "GatewayConfig", "verify_tool_result",
           "refusal_result", "HONEST_LIMITS"]

BUNDLE_KEY = "dev.arcaeon/bundle"
VERDICT_KEY = "dev.arcaeon/verdict"
DEFAULT_ACTION = "act"
HONEST_LIMITS = ("VERIFIED means the result's bytes are the bytes a key you named sealed, "
                 "labeled for you and in date. It does not say the content is true or safe, "
                 "and a server that seals nothing always reads COULD NOT LOOK.")
_CFG_KEYS = {"audience", "signers", "deal", "purpose", "enforce", "default_action", "tools"}
_TOOL_KEYS = {"action", "deal", "purpose"}


@dataclass(frozen=True)
class GatewayConfig:
    """What the receiver brings: who it is (audience), whose seals count
    (signers), the exchange (deal, purpose) and which action each tool's
    result stands for. Raises ValueError from from_dict on anything it cannot
    read, so a bad config fails at load, not quietly at call time."""
    audience: str | None = None
    signers: tuple = ()
    deal: str | None = None
    purpose: str | None = None
    enforce: str | None = None
    default_action: str = DEFAULT_ACTION
    tools: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict | None) -> "GatewayConfig":
        raw = dict(raw or {})
        extra = sorted(set(raw) - _CFG_KEYS)
        if extra:
            raise ValueError(f"unknown config key(s): {', '.join(extra)} "
                             f"(known: {', '.join(sorted(_CFG_KEYS))})")
        for k in ("audience", "deal", "purpose"):
            if raw.get(k) is not None and not isinstance(raw[k], str):
                raise ValueError(f"`{k}` must be a string")
        signers = raw.get("signers") or []
        if isinstance(signers, str):
            signers = [signers]
        if not isinstance(signers, list) or not all(isinstance(s, str) for s in signers):
            raise ValueError("`signers` must be a list of did:key strings")
        enforce = raw.get("enforce")
        if enforce is not None:
            enforce = GM.resolve(enforce).mode            # ValueError on an unknown word
        default = raw.get("default_action", DEFAULT_ACTION)
        _action(default, "default_action")
        tools = {}
        for name, v in (raw.get("tools") or {}).items():
            if isinstance(v, str):
                v = {"action": v}
            if not isinstance(v, dict) or set(v) - _TOOL_KEYS:
                raise ValueError(f"tools[{name!r}] must be an action word or an object with "
                                 f"{', '.join(sorted(_TOOL_KEYS))}")
            _action(v.get("action", default), f"tools[{name!r}].action")
            for k in ("deal", "purpose"):
                if v.get(k) is not None and not isinstance(v[k], str):
                    raise ValueError(f"tools[{name!r}].{k} must be a string")
            tools[str(name)] = dict(v)
        return cls(audience=raw.get("audience"), signers=tuple(signers), deal=raw.get("deal"),
                   purpose=raw.get("purpose"), enforce=enforce, default_action=default,
                   tools=tools)

    @classmethod
    def from_file(cls, path: str | Path) -> "GatewayConfig":
        raw = loads_strict(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: the config must be one JSON object")
        return cls.from_dict(raw)

    def for_tool(self, tool: str | None, server: str | None = None) -> dict:
        """{action, deal, purpose} for this tool: "server/tool" first, then
        "tool", then the defaults."""
        entry = {}
        for key in ((f"{server}/{tool}" if server and tool else None), tool):
            if key and key in self.tools:
                entry = self.tools[key]
                break
        return {"action": entry.get("action", self.default_action),
                "deal": entry.get("deal", self.deal),
                "purpose": entry.get("purpose", self.purpose)}


def _action(word, where: str) -> str:
    if word not in G.ACTIONS:
        raise ValueError(f"{where} must be one of {', '.join(G.ACTIONS)}; got {word!r}")
    return word


# --- the bytes a block offers ---------------------------------------------------------

def _b64(text) -> bytes:
    if not isinstance(text, str):
        raise ValueError("not a base64 string")
    return base64.b64decode(text, validate=True)


def _block_bytes(block: Any) -> tuple[bytes | None, str]:
    """(bytes, "") or (None, why). Never raises."""
    if not isinstance(block, dict):
        return None, "the content block is not an object"
    kind = block.get("type")
    try:
        if kind == "text" and isinstance(block.get("text"), str):
            return block["text"].encode("utf-8"), ""
        if kind in ("image", "audio") and "data" in block:
            return _b64(block["data"]), ""
        if kind == "resource" and isinstance(block.get("resource"), dict):
            res = block["resource"]
            if isinstance(res.get("text"), str):
                return res["text"].encode("utf-8"), ""
            if "blob" in res:
                return _b64(res["blob"]), ""
            return None, "the embedded resource has neither text nor blob"
    except (ValueError, binascii.Error):
        return None, f"the {kind} block's data is not base64"
    if kind == "resource_link":
        return None, "a resource_link carries a link, not bytes; nothing here can be sealed"
    return None, f"a content block of type {str(kind)[:40]!r} offers no bytes this check reads"


def _bundle(value: Any) -> tuple[dict | None, str]:
    if isinstance(value, str):
        if len(value.encode("utf-8")) > E.MAX_ENVELOPE_BYTES:
            return None, "the bundle is over the envelope size limit"
        try:
            value = loads_strict(value)
        except ValueError as e:
            return None, f"the bundle is not one JSON object ({str(e)[:80]})"
    if not isinstance(value, dict):
        return None, "the bundle is not an envelope object"
    return value, ""


def _meta(o: Any) -> dict:
    m = o.get("_meta") if isinstance(o, dict) else None
    return m if isinstance(m, dict) else {}


# --- decisions -------------------------------------------------------------------------

def _utc(now: datetime) -> str:
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cnl(action, ex, cfg, now, looked_for, where, word, reason) -> G.GateDecision:
    """A COULD NOT LOOK made before verify could run, by the gate's own rule
    and wording (the A2A receiver's shape)."""
    r = {"verdict": V.COULD_NOT_LOOK, **V.could_not_look(looked_for, where, word, reason)}
    allowed = action in G.RULES[V.COULD_NOT_LOOK]
    return G.GateDecision(decision=G.ALLOW if allowed else G.REFUSE, action=action,
                          verdict=V.COULD_NOT_LOOK,
                          reason=G._reason(action, V.COULD_NOT_LOOK, r, cfg.audience,
                                           ex["deal"]),
                          reasons=[reason],
                          could_not_check={k: r[k] for k in ("looked_for", "where",
                                                             "reason_word")},
                          file=where, envelope=where, audience=cfg.audience, deal=ex["deal"],
                          purpose=ex["purpose"], signers=list(cfg.signers), at=_utc(now),
                          report=r)


def _relabel(text, labels: dict):
    if isinstance(text, str):
        for path, label in labels.items():
            text = text.replace(path, label)
    return text


def _decide_one(data: bytes, env: dict, where: str, action, ex, cfg, now) -> G.GateDecision:
    with tempfile.TemporaryDirectory(prefix="arcaeon-mcp-") as td:
        f = Path(td) / "content"
        f.write_bytes(data)
        env_path = Path(td) / ("content" + E.SUFFIX)
        env_path.write_text(json.dumps(env), encoding="utf-8")
        d = G.decide(f, envelope=env_path, action=action, audience=cfg.audience,
                     signers=list(cfg.signers), deal=ex["deal"], purpose=ex["purpose"],
                     now=now, record=False)
        labels = {str(env_path): f"{where}._meta[{BUNDLE_KEY}]", str(f): where, td: where}
    d.reason = _relabel(d.reason, labels)
    d.reasons = [_relabel(s, labels) for s in d.reasons]
    if d.could_not_check:
        d.could_not_check = {k: _relabel(v, labels) for k, v in d.could_not_check.items()}
    d.file, d.envelope, d.report = where, f"{where}._meta[{BUNDLE_KEY}]", {}
    return d


_RANK = {V.BROKEN: 0, V.COULD_NOT_LOOK: 1, V.VERIFIED: 2}


def _worst(ds: list) -> G.GateDecision:
    """BROKEN over COULD NOT LOOK over VERIFIED; a refusal over an allow."""
    return min(ds, key=lambda d: (_RANK.get(d.verdict, 1), d.decision != G.REFUSE))


def _judge(result: dict, action: str, ex: dict, cfg: GatewayConfig, now) -> tuple:
    def cnl(looked_for, where, word, reason):
        return _cnl(action, ex, cfg, now, looked_for, where, word, reason)

    content = result.get("content")
    if content is None:
        content = []
    if not isinstance(content, list):
        return cnl("the result's content", "result.content", "unreadable",
                   "result.content is not a list"), []
    top = _meta(result).get(BUNDLE_KEY)
    per_block = [_meta(b).get(BUNDLE_KEY) for b in content]
    items, gaps = [], []                     # (where, bytes, bundle) / structural CNLs
    if top is not None and any(v is not None for v in per_block):
        gaps.append(cnl("one place for each seal", "result._meta", "bounded",
                        "a bundle on the result and on content blocks: put each seal on the "
                        "block it seals"))
    elif top is not None:
        if len(content) != 1:
            gaps.append(cnl("the one content block a result-level bundle seals", "result",
                            "bounded", f"a result-level {BUNDLE_KEY} with {len(content)} content "
                            f"blocks: seal each block on its own _meta"))
        else:
            items.append(("content[0]", content[0], top))
    else:
        for i, (b, v) in enumerate(zip(content, per_block)):
            if v is not None:
                items.append((f"content[{i}]", b, v))
    sealed = {w for w, _, _ in items}
    if not items and not gaps:
        gaps.append(cnl(f"an arcaeon bundle under _meta[{BUNDLE_KEY!r}]", "result", "missing",
                        f"no {BUNDLE_KEY} on the result or any content block: nothing says who "
                        f"sealed these bytes (an unsealed server always reads COULD NOT LOOK)"))
    elif top is None:
        for i in range(len(content)):
            if f"content[{i}]" not in sealed:
                gaps.append(cnl(f"a seal on content[{i}]", f"content[{i}]", "missing",
                                f"content[{i}] carries no {BUNDLE_KEY}: the model would read "
                                f"bytes no seal covers"))
    ds, texts = [], []
    for where, block, raw in items:
        env, why = _bundle(raw)
        data, why2 = _block_bytes(block) if env is not None else (None, "")
        if env is None:
            ds.append(cnl("an arcaeon envelope", f"{where}._meta[{BUNDLE_KEY}]", "unreadable",
                          why))
        elif data is None:
            ds.append(cnl(f"the bytes {where} offers", where, "unreadable", why2))
        else:
            d = _decide_one(data, env, where, action, ex, cfg, now)
            ds.append(d)
            if d.verdict == V.VERIFIED and isinstance(block, dict):
                txt = block.get("text") if block.get("type") == "text" else (
                    (block.get("resource") or {}).get("text")
                    if block.get("type") == "resource" else None)
                if isinstance(txt, str):
                    texts.append(txt)
    sc = result.get("structuredContent")
    if sc is not None and not _covered(sc, texts):
        gaps.append(cnl("a sealed text block holding structuredContent", "structuredContent",
                        "missing", "structuredContent is not the same JSON as any sealed text "
                        "block: the model would read JSON no seal covers"))
    return _worst(ds + gaps), ds + gaps


def _canon(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _covered(sc, texts: list) -> bool:
    want = _canon(sc)
    for t in texts:
        try:
            if _canon(loads_strict(t)) == want:
                return True
        except ValueError:
            continue
    return False


def _mode(cfg: GatewayConfig, enforce):
    try:
        return GM.resolve(enforce if enforce is not None else cfg.enforce), None
    except ValueError as e:
        return GM.Mode(GM.BLOCK, "default", f"{e}: block (fail closed)"), str(e)


def _summary(d: G.GateDecision, tool, parts: list) -> dict:
    out = {"verdict": d.verdict, "decision": d.decision, "action": d.action, "tool": tool,
           "reason": d.reason, "reasons": list(d.reasons),
           "could_not_check": dict(d.could_not_check) if d.could_not_check else None,
           "would_refuse": d.would_refuse, "warning": d.warning,
           "enforce_mode": d.enforce_mode, "enforce_source": d.enforce_source,
           "enforce_detail": d.enforce_detail, "audience": d.audience, "deal": d.deal,
           "purpose": d.purpose, "at": d.at, "honest_limits": HONEST_LIMITS}
    if len(parts) > 1:
        out["parts"] = [{"where": p.file, "verdict": p.verdict, "decision": p.decision}
                        for p in parts]
    return out


def refusal_result(summary: dict, original: dict | None = None) -> dict:
    """The result the model sees instead: isError true, one plain text block,
    none of the tool's own content. `resultType` is kept when the original
    had one (MCP 2026-07-28 requires it)."""
    word = summary.get("verdict") or V.COULD_NOT_LOOK
    text = (f"REFUSED by arcaeon: {word}. {summary.get('reason') or ''} "
            f"The tool's output was withheld and not shown.").strip()
    out = {"content": [{"type": "text", "text": text}], "isError": True,
           "_meta": {VERDICT_KEY: summary}}
    if isinstance(original, dict) and "resultType" in original:
        out["resultType"] = original["resultType"]
    return out


def verify_tool_result(result_json: Any, *, action: str | None = None,
                       enforce: str | None = None, config: GatewayConfig | dict | None = None,
                       tool: str | None = None, server: str | None = None,
                       now: datetime | None = None) -> tuple[dict, dict]:
    """(new_result, decision) for one MCP CallToolResult (a dict).

    `action` overrides the config's per-tool action; None reads it from the
    config for `tool` (default "act"). `enforce` overrides the config's;
    both None reads ARCAEON_GATE_MODE, then the cached signed latest.json,
    else block. `decision` is the dict also put under
    _meta["dev.arcaeon/verdict"]. Raises ValueError only on a caller error
    (an unknown action word, a config it cannot read); a hostile result is
    an answer (COULD NOT LOOK), never an exception."""
    cfg = config if isinstance(config, GatewayConfig) else GatewayConfig.from_dict(config)
    ex = cfg.for_tool(tool, server)
    action = _action(action if action is not None else ex["action"], "action")
    ex["action"] = action
    now = now or datetime.now(timezone.utc)
    mode, bad_mode = _mode(cfg, enforce)
    try:
        if not isinstance(result_json, dict):
            d, parts = _cnl(action, ex, cfg, now, "an MCP tool result", "result", "unreadable",
                            "the tool result is not a JSON object"), []
        else:
            d, parts = _judge(result_json, action, ex, cfg, now)
    except Exception as e:  # noqa: BLE001  never a traceback, never a green
        d, parts = _cnl(action, ex, cfg, now, "a finished check", "result", "unreadable",
                        f"the check could not finish ({type(e).__name__})"), []
    if bad_mode is not None:                      # an unreadable mode refuses, loudly
        d.reasons.append(bad_mode)
    d = G._enforce(d, mode)
    summary = _summary(d, tool, parts)
    if d.decision == G.REFUSE:
        return refusal_result(summary, result_json if isinstance(result_json, dict) else None), \
            summary
    out = copy.deepcopy(result_json)
    meta = out.get("_meta") if isinstance(out.get("_meta"), dict) else {}
    out["_meta"] = {**meta, VERDICT_KEY: summary}
    return out, summary
