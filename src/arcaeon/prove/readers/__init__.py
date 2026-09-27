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
`unreadable` when the answer came back in a shape we cannot read,
`redirect_refused` when the endpoint answered with a redirect). A failed
call never becomes a reading: the caller writes nothing for that claim.

NO REDIRECTS, NO PROXIES (K036R). A reader talks to the endpoint it was
given and to nothing else. A 3xx answer is never followed: following it
would copy the key header (`Authorization`, `x-api-key`, `x-goog-api-key`)
to whatever host the `Location` names, https to http included, and the
answer would be recorded under the original `endpoint_host`. It is a
`redirect_refused` error naming the Location host. Proxy settings
(`HTTP_PROXY`, `HTTPS_PROXY`, the Windows registry) are ignored, so a key
never passes through a proxy the caller did not name.

PRESETS (`reader_from_spec`, the CLI's `--reader`). `ollama:<model>` is the
OpenAI-compatible reader at `OLLAMA_BASE_URL` (`http://127.0.0.1:11434/v1`,
no key), provider `ollama`. `openai_compat:<model>` needs a `base_url`;
`anthropic:<model>` and `gemini:<model>` need a `key_env`.

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
           "ReaderCallError", "Reader", "build_prompt", "parse_answer", "post_json",
           "OLLAMA_BASE_URL", "PRESETS", "reader_from_spec"]

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


def _opener():
    """A urllib opener that follows no redirect and uses no proxy."""
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # never follow: the 3xx surfaces as an HTTPError

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def post_json(url: str, body: dict, headers: dict, timeout: float) -> Any:
    """POST a JSON body, return the decoded JSON answer. Raises ReaderCallError.

    Talks to `url` only: no redirect is followed and no proxy is used (see
    NO REDIRECTS, NO PROXIES above). No error message carries a header value
    (a key rides in the headers).
    """
    import urllib.error
    import urllib.request
    from urllib.parse import urljoin
    host = urlsplit(url).hostname or "?"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with _opener().open(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            # OA2: parsing the Location runs inside this handler, where the
            # sibling `except ... ValueError` below cannot catch it, so a bad
            # port or host is caught here and refused like any redirect.
            try:
                loc = e.headers.get("Location") if e.headers is not None else None
                parts = urlsplit(urljoin(url, loc)) if loc else None
                to = (parts.hostname if parts else None) or "no Location host"
                to_port = parts.port if parts else None
                target = f"redirecting to {to}:{to_port}" if to_port else f"redirecting to {to}"
            except ValueError as bad:
                target = f"with a Location that could not be read ({bad})"
            raise ReaderCallError(f"redirect refused: {host} answered HTTP {e.code} {target}; "
                                  "not followed, the key was not sent there",
                                  "redirect_refused") from None
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


#: Ollama's OpenAI-compatible endpoint on this machine (loopback only).
OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1"

#: `--reader` prefixes: prefix -> (module, class name, fixed base_url or None).
PRESETS = {
    "ollama": ("arcaeon.prove.readers.openai_compat", "OpenAICompatReader", OLLAMA_BASE_URL),
    "openai_compat": ("arcaeon.prove.readers.openai_compat", "OpenAICompatReader", None),
    "anthropic": ("arcaeon.prove.readers.anthropic", "AnthropicReader", None),
    "gemini": ("arcaeon.prove.readers.gemini", "GeminiReader", None),
}


def reader_from_spec(spec: str, *, base_url: str | None = None, key_env: str | None = None,
                     reader_id: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> Reader:
    """A reader from a `--reader` spec such as `ollama:qwen2.5-coder:3b`.

    The text before the FIRST colon is the preset; everything after it is the
    model name (so model tags with colons pass through whole). `ollama:` fixes
    the base URL to OLLAMA_BASE_URL (a `base_url` given with it is refused, so
    a spec never quietly points somewhere else). Raises ReaderError.
    """
    import importlib
    if not isinstance(spec, str) or ":" not in spec:
        raise ReaderError(f"reader spec must look like <preset>:<model>, got {spec!r}; "
                          f"presets: {', '.join(PRESETS)}")
    preset, model = spec.split(":", 1)
    if preset not in PRESETS:
        raise ReaderError(f"unknown reader preset {preset!r}; presets: {', '.join(PRESETS)}")
    if not model.strip():
        raise ReaderError(f"reader spec {spec!r} names no model")
    mod, cls_name, fixed = PRESETS[preset]
    cls = getattr(importlib.import_module(mod), cls_name)
    kw: dict = {"model": model, "reader_id": reader_id, "timeout": timeout}
    if fixed is not None:
        if base_url is not None and base_url.rstrip("/") != fixed:
            raise ReaderError(f"{preset}: always reads at {fixed}; use openai_compat: for another host")
        kw.update(base_url=fixed, provider=preset)
        if key_env:
            kw["key_env"] = key_env
    elif cls_name == "OpenAICompatReader":
        if not base_url:
            raise ReaderError("openai_compat: needs a base_url (--base-url)")
        kw.update(base_url=base_url, key_env=key_env)
    else:
        if not key_env:
            raise ReaderError(f"{preset}: needs key_env (--key-env, the variable holding the key)")
        kw["key_env"] = key_env
        if base_url:
            kw["base_url"] = base_url
    return cls(**kw)
