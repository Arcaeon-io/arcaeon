# SPDX-License-Identifier: MIT
"""arcaeon.prove.datadog_llmobs: arcaeon verdicts as a Datadog LLM Observability
span payload (L2-13). An EXPORT: it builds the JSON body and sends nothing.

    from arcaeon.prove import datadog_llmobs as dd
    body = dd.to_llmobs(report)                # an `envelope verify` report, a
                                               # `gate decide --json` decision, a
                                               # gate evidence pack's evidence.json,
                                               # or a JSON list of them
    body = dd.to_llmobs(report, now=fixed_utc_time, ml_app="checks", service="svc")

The body is the one Datadog documents for its LLM Observability HTTP intake,
`POST https://api.<site>/api/intake/llm-obs/v1/trace/spans`, read on
2026-10-05 from https://docs.datadoghq.com/llm_observability/setup/api/
("Spans API"). Every field name below is one that page lists; none is
invented:

    {"data": {"type": "span",
              "attributes": {"ml_app": ..., "tags": [...],
                             "spans": [{"name", "span_id", "trace_id", "parent_id",
                                        "start_ns", "duration", "status",
                                        "meta": {"kind", "input", "output",
                                                 "metadata", "error"},
                                        "metrics", "tags", "service"}]}}}

One verdict is one span in its own trace (parent_id "undefined", the page's
word for a root span), meta.kind "task".

    verdict          status   tag                               meta.error
    VERIFIED         ok       arcaeon.verdict:VERIFIED          none
    BROKEN           error    arcaeon.verdict:BROKEN            type arcaeon.BROKEN
    COULD NOT LOOK   ok       arcaeon.verdict:COULD_NOT_LOOK    none
      gate refused   error    arcaeon.verdict:COULD_NOT_LOOK    none

Every span carries exactly one arcaeon.verdict tag, in the token form above
(tags take no spaces; meta.metadata keeps the word with its spaces). A
COULD NOT LOOK on a gate input whose decision is refuse is an error span:
the action was stopped. Any other COULD NOT LOOK stays ok.

All three are emitted (a trace of every check is the point). A gate refusal
of a VERIFIED envelope is never VERIFIED: it reads BROKEN on checker-broken
and COULD NOT LOOK on any other veto, as in the OCSF export, with the
envelope's own word in arcaeon.envelope_verdict.

CONTENT NEVER LEAVES. The span carries digests, verdict words and words from
fixed sets (the gate's four actions, allow/refuse, the three vetoes, the
COULD NOT LOOK reason words), never payload text: no reasons, findings,
labels, deal, audience, purpose, signer keys, file names or directories.
meta.input.value is "sha256:<hex>" of the checked file when the input carries
it, else of the arcaeon input document (canonical JSON); meta.output.value is
"sha256:<hex>" of the normalized verdict record. A reader who holds the
arcaeon report can match it to the span; nobody else learns its content.

IDS ARE DIGESTS. trace_id is 32 hex characters and span_id a decimal string
of a 63-bit number, both cut from SHA-256 over the verdict record digest, so
the same check gives the same ids on every export. The page only says
"string" for both; the formats are our choice. start_ns is the export time
(--now fixes it); duration is 0 (a verdict is a point, not a timed call).

NO SEND, NO KEY. Nothing here opens a connection or reads a key. The sender
supplies DD-API-KEY (and Content-Type: application/json) in their own
pipeline. The page says the intake accepts spans no more than 24 hours old,
which is why start_ns is the export time, not the check time (the check time
rides in meta.metadata as arcaeon.checked_at).

Pure apart from the CLI's file read and write. Given the same input and the
same `now` the output is byte-identical.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import ocsf as _ocsf

__all__ = ["DOC_URL", "DOC_READ_ON", "INTAKE_PATH", "SPAN_KIND", "DEFAULT_ML_APP", "MAX_SPANS",
           "VERDICT_TAG", "STATUS", "STATUS_REFUSED_COULD_NOT_LOOK", "LIMITS_LINE", "ExportError", "to_llmobs", "dumps",
           "export_cli", "main"]

#: The page every field name was read from, and when.
DOC_URL = "https://docs.datadoghq.com/llm_observability/setup/api/"
DOC_READ_ON = "2026-10-05"
#: The intake path the body is for (on https://api.<your Datadog site>).
INTAKE_PATH = "/api/intake/llm-obs/v1/trace/spans"
#: One of the page's span kinds: agent, workflow, llm, tool, task, embedding, retrieval.
SPAN_KIND = "task"
DEFAULT_ML_APP = "arcaeon"
MAX_SPANS = 1000
#: The page's word for "no parent" on a root span.
ROOT_PARENT = "undefined"
EXPORT_TAG = "arcaeon.export:dd-llmobs-v1"

#: verdict word -> tag value (tags take no spaces) and span status
VERDICT_TAG = {V.VERIFIED: "VERIFIED", V.BROKEN: "BROKEN", V.COULD_NOT_LOOK: "COULD_NOT_LOOK"}
STATUS = {V.VERIFIED: "ok", V.BROKEN: "error", V.COULD_NOT_LOOK: "ok"}
#: COULD NOT LOOK on a gate input whose decision is refuse (the action was
#: stopped) is an error span, as OCSF makes it an alert.
STATUS_REFUSED_COULD_NOT_LOOK = "error"
LIMITS_LINE = _ocsf.LIMITS_LINE

ExportError = _ocsf.ExportError

_NAME = {"verify report": "arcaeon.envelope.verify", "gate decision": "arcaeon.gate.decide",
         "gate evidence pack": "arcaeon.gate.evidence_pack"}
_SOURCE_TAG = {"verify report": "verify_report", "gate decision": "gate_decision",
               "gate evidence pack": "gate_evidence_pack"}
#: Fixed word sets that may ride in tags (named here, not imported, as in ocsf).
_ACTIONS = ("read", "act", "pay", "irreversible")
_DECISIONS = ("allow", "refuse")
_VETOES = ("checker-broken", "checks-unreadable", "nonparty-check")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})")
#: The page's application naming guidelines: lowercase; alphanumerics,
#: underscores, minuses, colons, periods, slashes; up to 193 characters; no
#: contiguous or trailing underscores. (ASCII only here: stricter than the page.)
_ML_APP = re.compile(r"[a-z0-9_\-:./]{1,193}")
_SERVICE = re.compile(r"[A-Za-z0-9_\-:./]{1,100}")
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_BROKEN_MESSAGE = ("BROKEN: a check came out wrong. The reasons stay in the arcaeon report; "
                   "this span carries digests and verdict words only.")


def _check_ml_app(name: Any) -> str:
    if not (isinstance(name, str) and _ML_APP.fullmatch(name) and "__" not in name
            and not name.endswith("_")):
        raise ValueError(f"ml_app {name!r} does not follow Datadog's application naming "
                         "guidelines (lowercase a-z 0-9 _ - : . /, at most 193, no __ or "
                         "trailing _)")
    return name


def _check_service(name: Any) -> str | None:
    if name is None:
        return None
    if not (isinstance(name, str) and _SERVICE.fullmatch(name)):
        raise ValueError(f"service {name!r} is not 1 to 100 of A-Z a-z 0-9 _ - : . /")
    return name


def _ns(now: datetime) -> int:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return ((now - _EPOCH) // timedelta(microseconds=1)) * 1000


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _ids(record_sha: str) -> tuple[str, str]:
    """(trace_id, span_id) from the record digest: 32 hex, and a decimal 63-bit."""
    trace = hashlib.sha256(b"arcaeon.dd-llmobs.trace.v1\n" + record_sha.encode()).hexdigest()
    span = hashlib.sha256(b"arcaeon.dd-llmobs.span.v1\n" + record_sha.encode()).digest()
    n = int.from_bytes(span[:8], "big") >> 1
    return trace[:32], str(n or 1)


def _span(obj: Any, start_ns: int, service: str | None) -> dict:
    rec = _ocsf.normalize(obj)                   # raises ExportError; scrubs paths
    word = _ocsf._word(rec)                      # a gate refusal is never VERIFIED
    record_sha = _sha(_canon(rec))
    trace_id, span_id = _ids(record_sha)
    file_sha = rec.get("file_sha256") if isinstance(rec.get("file_sha256"), str) else None
    if file_sha and _HEX64.fullmatch(file_sha):
        in_value, in_of = "sha256:" + file_sha, "the checked file"
    else:
        file_sha = None
        in_value, in_of = "sha256:" + _sha(_canon(obj)), "the arcaeon input document"
    tags = [f"arcaeon.verdict:{VERDICT_TAG[word]}",
            f"arcaeon.source:{_SOURCE_TAG[rec['source']]}",
            f"arcaeon.record_sha256:{record_sha}"]
    meta_md: dict[str, Any] = {"arcaeon.verdict": word, "arcaeon.source": rec["source"],
                               "arcaeon.input_digest_of": in_of, "arcaeon.limits": LIMITS_LINE}
    if word != rec["verdict"]:
        tags.append(f"arcaeon.envelope_verdict:{VERDICT_TAG[rec['verdict']]}")
        meta_md["arcaeon.envelope_verdict"] = rec["verdict"]
    if rec.get("action") in _ACTIONS:
        tags.append(f"arcaeon.action:{rec['action']}")
    if rec.get("decision") in _DECISIONS:
        tags.append(f"arcaeon.decision:{rec['decision']}")
    if rec.get("veto") in _VETOES:
        tags.append(f"arcaeon.veto:{rec['veto']}")
    cnc = rec.get("could_not_check") or {}
    if word == V.COULD_NOT_LOOK and cnc.get("reason_word") in V.REASON_WORDS:
        tags.append(f"arcaeon.could_not_look:{cnc['reason_word']}")
    if file_sha:
        tags.append(f"arcaeon.file_sha256:{file_sha}")
    env_sha = rec.get("envelope_sha256")
    if isinstance(env_sha, str) and _HEX64.fullmatch(env_sha):
        tags.append(f"arcaeon.envelope_sha256:{env_sha}")
    if isinstance(rec.get("checked_at"), str) and _ISO.fullmatch(rec["checked_at"]):
        meta_md["arcaeon.checked_at"] = rec["checked_at"]
    metrics = {"arcaeon.verified": float(word == V.VERIFIED),
               "arcaeon.broken": float(word == V.BROKEN),
               "arcaeon.could_not_look": float(word == V.COULD_NOT_LOOK),
               "arcaeon.not_checked": float(len(rec.get("not_checked") or []))}
    if isinstance(rec.get("checks"), dict):
        metrics["arcaeon.checks_broken"] = float(rec["checks"].get("broken_count") or 0)
    meta: dict[str, Any] = {"kind": SPAN_KIND, "input": {"value": in_value},
                            "output": {"value": "sha256:" + record_sha}, "metadata": meta_md}
    if word == V.BROKEN:
        meta["error"] = {"type": "arcaeon.BROKEN", "message": _BROKEN_MESSAGE}
    status = STATUS[word]
    if word == V.COULD_NOT_LOOK and rec.get("decision") == "refuse":
        status = STATUS_REFUSED_COULD_NOT_LOOK
    span: dict[str, Any] = {"name": _NAME[rec["source"]], "span_id": span_id,
                            "trace_id": trace_id, "parent_id": ROOT_PARENT,
                            "start_ns": start_ns, "duration": 0, "status": status,
                            "meta": meta, "metrics": metrics, "tags": tags}
    if service:
        span["service"] = service
    return span


def to_llmobs(obj: Any, *, now: datetime | None = None, ml_app: str = DEFAULT_ML_APP,
              service: str | None = None) -> dict:
    """The LLM Observability spans body for one arcaeon verdict, or for a JSON
    list of them (one span each, at most MAX_SPANS). Raises ExportError on an
    input that is not an arcaeon verdict, ValueError on an ml_app or service
    name outside the rules above. Sends nothing."""
    ml_app = _check_ml_app(ml_app)
    service = _check_service(service)
    items = obj if isinstance(obj, list) else [obj]
    if not items:
        raise ExportError("the input lists no verdicts")
    if len(items) > MAX_SPANS:
        raise ExportError(f"the input lists {len(items)} verdicts, over {MAX_SPANS}")
    start_ns = _ns(now or datetime.now(timezone.utc))
    spans = [_span(x, start_ns, service) for x in items]
    return {"data": {"type": "span",
                     "attributes": {"ml_app": ml_app, "tags": [EXPORT_TAG], "spans": spans}}}


def dumps(body: dict) -> str:
    """The body as deterministic JSON text (sorted keys, one trailing newline)."""
    return json.dumps(body, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def export_cli(argv: list[str], parse, usage_error) -> int:
    """`arcaeon envelope export-datadog INPUT [--ml-app NAME] [--service NAME]
    [--now WHEN] [--out FILE]`: writes the body; never sends it."""
    pos, o = parse(argv, {"--ml-app": "value", "--service": "value", "--now": "value",
                          "--out": "value"})
    if len(pos) != 1:
        raise usage_error("export-datadog takes one input (a JSON file, or - for stdin)")
    try:
        now = _ocsf._parse_now(o["--now"]) if o.get("--now") else None
        _check_ml_app(o.get("--ml-app") or DEFAULT_ML_APP)
        _check_service(o.get("--service"))
    except ValueError as e:
        raise usage_error(str(e)) from e
    try:
        body = to_llmobs(_ocsf.read_input(pos[0]), now=now,
                         ml_app=o.get("--ml-app") or DEFAULT_ML_APP, service=o.get("--service"))
    except ExportError as e:
        print(f"arcaeon envelope export-datadog: {V.COULD_NOT_LOOK}: {e}; nothing was exported",
              file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    text = dumps(body)
    if o.get("--out"):
        Path(o["--out"]).write_text(text, encoding="utf-8", newline="\n")
        print(o["--out"])
    else:
        sys.stdout.write(text)
    return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:  # pragma: no cover  (envelope.main wires it)
    from arcaeon.prove import envelope as E
    try:
        return export_cli(list(sys.argv[1:] if argv is None else argv), E._parse, E._Usage)
    except E._Usage as e:
        print(f"arcaeon envelope export-datadog: {e}", file=sys.stderr)
        return V.EXIT_USAGE
