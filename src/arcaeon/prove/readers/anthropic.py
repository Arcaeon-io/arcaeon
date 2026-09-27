# SPDX-License-Identifier: MIT
"""arcaeon.prove.readers.anthropic: the Anthropic Messages API as a second reader.

`POST {base_url}/v1/messages` (default base `https://api.anthropic.com`) with
one user message and temperature 0. Headers: `x-api-key`, read from the
variable named by `key_env` at call time (required), and `anthropic-version`.
The answer is the text blocks of `content`, joined in order; it goes through
the same strict first-word parse as every reader.

Stdlib only.
"""
from __future__ import annotations

from arcaeon.prove.readers import DEFAULT_TIMEOUT, Reader, ReaderCallError, post_json

__all__ = ["AnthropicReader", "DEFAULT_BASE_URL", "ANTHROPIC_VERSION"]

DEFAULT_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicReader(Reader):
    """A second reader on the Anthropic Messages API."""

    default_provider = "anthropic"
    key_required = True

    def __init__(self, *, model: str, key_env: str, base_url: str = DEFAULT_BASE_URL,
                 reader_id: str | None = None, provider: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT, anthropic_version: str = ANTHROPIC_VERSION):
        super().__init__(base_url=base_url, model=model, key_env=key_env, reader_id=reader_id,
                         provider=provider, timeout=timeout)
        self.anthropic_version = anthropic_version

    def _call(self, prompt: str) -> str:
        headers = {"x-api-key": self._key(), "anthropic-version": self.anthropic_version}
        body = {"model": self.model, "max_tokens": 16, "temperature": 0,
                "messages": [{"role": "user", "content": prompt}]}
        ans = post_json(f"{self.base_url}/v1/messages", body, headers, self.timeout)
        blocks = ans.get("content") if isinstance(ans, dict) else None
        if not isinstance(blocks, list):
            raise ReaderCallError(f"{self.endpoint_host} answered without a content list",
                                  "unreadable")
        texts = [b.get("text") for b in blocks
                 if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)]
        if not texts:
            raise ReaderCallError(f"{self.endpoint_host} answered without a text block",
                                  "unreadable")
        return "".join(texts)
