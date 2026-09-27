# SPDX-License-Identifier: MIT
"""arcaeon.prove.readers: other models as second readers, behind one interface.

A READER takes one frozen criterion sentence and one claim, asks a model one
question, and turns the answer into one `arcaeon-reading/1` row (see
`arcaeon.prove.readings`). It says what that model answered, nothing more:
the row is a reading of a sentence, not a finding about the claim.

THE INTERFACE. Every backend is a `Reader` subclass that implements
`_call(prompt) -> str` (the model's raw answer text). `Reader.read(...)`
does the rest the same way for every backend: build the prompt from the
frozen template, call, parse by the strict first-word rule, build the row.
Tests point a backend at a 127.0.0.1 stub; nothing here reaches a real model
unless a caller passes a real endpoint.

THE PROMPT. `PROMPT_TEMPLATE` is frozen; its sha256 is
`PROMPT_TEMPLATE_SHA256` and rides in each row as `prompt_template_sha256`.
The exact prompt sent (template filled with the criterion and the claim) is
hashed into the row's `prompt_sha256`.

THE PARSE (`parse_answer`). The answer's first word, lowercased, with
trailing punctuation dropped, must be `yes`, `no` or `undetermined`. Anything
else (an empty answer, a hedge, a paragraph that starts somewhere else) is
`undetermined`. The raw answer's sha256 is kept either way as the row's
`rationale_sha256`; its text is kept only with `keep_text=True`.

THE KEY. A key comes from an environment variable NAMED by the caller
(`key_env`, the CLI's `--key-env`), never from argv, never written to a row,
never put in an error message or a log line. Errors name the variable, not
its value.

A failed call raises `ReaderCallError` with a `reason_word` from
`arcaeon.verdict.REASON_WORDS` (`network` when the request never completed,
`unreadable` when the answer came back in a shape we cannot read). A failed
call never becomes a reading: the caller writes nothing for that claim.

Stdlib only (`urllib`, imported when a call is made).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlsplit

from arcaeon.prove.readings import (READING_WORDS, build_reading, normalize_criterion,
                                    sha256_text)

__all__ = ["PROMPT_TEMPLATE", "PROMPT_TEMPLATE_SHA256", "DEFAULT_TIMEOUT", "ReaderError",
           "ReaderCallError", "Reader", "build_prompt", "parse_answer", "post_json"]

#: The frozen question. Changing one byte changes PROMPT_TEMPLATE_SHA256,
#: which every row carries, so a reading taken under another template shows.
PROMPT_TEMPLATE = (
    "You are one of two readers. Read the claim below against the criterion below.\n"
    "Answer with exactly one word first: yes, no, or undetermined.\n"
    "yes: the claim meets the criterion. no: it does not. "
    "undetermined: the criterion cannot be applied to this claim as written.\n"
    "\n"
    "Criterion:\n{criterion}\n"
    "\n"
    "Claim:\n{claim}\n"
    "\n"
    "Answer:"
)
PROMPT_TEMPLATE_SHA256 = sha256_text(PROMPT_TEMPLATE)

#: Seconds per call (the batch rule: 30 s timeout per call).
DEFAULT_TIMEOUT = 30.0

_TRAIL = re.compile(r"[\s.,;:!?\"'`*)\]]+\Z")
_LEAD = re.compile(r"\A[\s\"'`*(\[]+")


class ReaderError(ValueError):
    """A reader that cannot be set up as asked (bad endpoint, key variable unset)."""


class ReaderCallError(RuntimeError):
    """One call to a model did not produce an answer we can read."""

    def __init__(self, message: str, reason_word: str = "network"):
        super().__init__(message)
        self.reason_word = reason_word


def build_prompt(criterion_text: str, claim_text: str) -> str:
    """The exact prompt for one claim: the frozen template, filled."""
    return PROMPT_TEMPLATE.format(criterion=normalize_criterion(criterion_text), claim=claim_text)


def parse_answer(answer: Any) -> str:
    """The strict first-word rule. Returns one of READING_WORDS."""
    if not isinstance(answer, str):
        return "undetermined"
    text = _LEAD.sub("", answer)
    if not text:
        return "undetermined"
    first = text.split(None, 1)[0]
    word = _TRAIL.sub("", first).casefold()
    return word if word in READING_WORDS else "undetermined"


def post_json(url: str, body: dict, headers: dict, timeout: float) -> Any:
    """POST a JSON body, return the decoded JSON answer. Raises ReaderCallError.

    No error message carries a header value (a key rides in the headers).
    """
    import urllib.error
    import urllib.request
    host = urlsplit(url).hostname or "?"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raise ReaderCallError(f"{host} answered HTTP {e.code}", "network") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise ReaderCallError(f"the request to {host} did not complete [{type(e).__name__}]",
                              "network") from None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ReaderCallError(f"{host} answered with something that is not JSON",
                              "unreadable") from None


class Reader:
    """One model at one endpoint, as a second reader. Subclasses set
    `default_provider` and implement `_call(prompt) -> str`."""

    default_provider = "unknown"
    key_required = False

    def __init__(self, *, base_url: str, model: str, key_env: str | None = None,
                 reader_id: str | None = None, provider: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT):
        parts = urlsplit(base_url or "")
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ReaderError(f"base_url must be an http(s) URL with a host, got {base_url!r}")
        if not isinstance(model, str) or not model.strip():
            raise ReaderError("model must be a non-empty string")
        if key_env is not None and (not isinstance(key_env, str) or not key_env.strip()):
            raise ReaderError("key_env must name an environment variable")
        if self.key_required and not key_env:
            raise ReaderError(f"{type(self).__name__} needs key_env (the variable holding the key)")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.key_env = key_env
        self.endpoint_host = parts.hostname
        self.provider = provider or self.default_provider
        self.reader_id = reader_id or f"{self.provider}:{model}@{parts.hostname}"
        self.timeout = float(timeout)

    def __repr__(self) -> str:  # never shows a key: it is not held here
        return f"{type(self).__name__}(id={self.reader_id!r}, host={self.endpoint_host!r})"

    @property
    def reader_info(self) -> dict:
        return {"id": self.reader_id, "provider": self.provider, "model": self.model,
                "endpoint_host": self.endpoint_host}

    def _key(self) -> str | None:
        """The key, read from the named variable at call time. Never stored."""
        if not self.key_env:
            return None
        val = os.environ.get(self.key_env)
        if not val:
            raise ReaderError(f"environment variable {self.key_env} is not set")
        return val

    def _call(self, prompt: str) -> str:  # pragma: no cover  the interface
        raise NotImplementedError

    def ask(self, prompt: str) -> str:
        """Send one prompt; the raw answer text. Raises ReaderCallError."""
        answer = self._call(prompt)
        if not isinstance(answer, str):
            raise ReaderCallError(f"{self.endpoint_host} answered without text", "unreadable")
        return answer

    def read(self, *, claim_id: str, claim_text: str, criterion_text: str,
             near_match_id: str | None = None, keep_text: bool = False) -> dict:
        """Ask about one claim; return one built reading row (not yet written).

        Raises ReaderCallError when the call fails: no reading is guessed.
        """
        prompt = build_prompt(criterion_text, claim_text)
        answer = self.ask(prompt)
        row = build_reading(claim_id=claim_id, claim_text=claim_text,
                            criterion_sha256=sha256_text(normalize_criterion(criterion_text)),
                            reader=self.reader_info, reading=parse_answer(answer),
                            near_match_id=near_match_id, rationale=answer, keep_text=keep_text,
                            prompt_sha256=sha256_text(prompt))
        row["prompt_template_sha256"] = PROMPT_TEMPLATE_SHA256
        return row
