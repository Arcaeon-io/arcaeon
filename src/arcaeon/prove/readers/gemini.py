# SPDX-License-Identifier: MIT
"""arcaeon.prove.readers.gemini: the Gemini generateContent API as a second reader.

`POST {base_url}/v1beta/models/{model}:generateContent` (default base
`https://generativelanguage.googleapis.com`) with one user turn, temperature
0. The key is read from the variable named by `key_env` at call time
(required) and sent in the `x-goog-api-key` header, never in the URL, so it
cannot leak through a logged address. The answer is the text parts of
`candidates[0].content.parts`, joined in order; it goes through the same
strict first-word parse as every reader.

Stdlib only.
"""
from __future__ import annotations

from urllib.parse import quote

from arcaeon.prove.readers import DEFAULT_TIMEOUT, Reader, ReaderCallError, post_json

__all__ = ["GeminiReader", "DEFAULT_BASE_URL", "API_VERSION"]

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com"
API_VERSION = "v1beta"


class GeminiReader(Reader):
    """A second reader on the Gemini `generateContent` API."""

    default_provider = "google"
    key_required = True

    def __init__(self, *, model: str, key_env: str, base_url: str = DEFAULT_BASE_URL,
                 reader_id: str | None = None, provider: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT, api_version: str = API_VERSION):
        super().__init__(base_url=base_url, model=model, key_env=key_env, reader_id=reader_id,
                         provider=provider, timeout=timeout)
        self.api_version = api_version

    def _url(self) -> str:
        model = self.model if self.model.startswith("models/") else f"models/{self.model}"
        return f"{self.base_url}/{self.api_version}/{quote(model, safe='/.-_')}:generateContent"

    def _call(self, prompt: str) -> str:
        headers = {"x-goog-api-key": self._key()}
        body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0, "maxOutputTokens": 16}}
        ans = post_json(self._url(), body, headers, self.timeout)
        try:
            parts = ans["candidates"][0]["content"]["parts"]
        except (KeyError, IndexError, TypeError):
            raise ReaderCallError(f"{self.endpoint_host} answered without candidates[0].content.parts",
                                  "unreadable") from None
        texts = [p.get("text") for p in parts if isinstance(p, dict) and isinstance(p.get("text"), str)] \
            if isinstance(parts, list) else []
        if not texts:
            raise ReaderCallError(f"{self.endpoint_host} answered without a text part",
                                  "unreadable")
        return "".join(texts)
