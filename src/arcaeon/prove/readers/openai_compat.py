# SPDX-License-Identifier: MIT
"""arcaeon.prove.readers.openai_compat: any OpenAI-compatible chat endpoint.

`POST {base_url}/chat/completions` with one user message and temperature 0.
That one shape covers OpenAI, Ollama (`http://127.0.0.1:11434/v1`),
OpenRouter, vLLM, LM Studio, Groq, Together, Mistral and any host that speaks
it. The key, when there is one, is read from the variable named by `key_env`
at call time and sent as `Authorization: Bearer ...`; a local server with no
key needs no `key_env`.

The answer is `choices[0].message.content`. Stdlib only.
"""
from __future__ import annotations

from arcaeon.prove.readers import Reader, ReaderCallError, post_json

__all__ = ["OpenAICompatReader"]


class OpenAICompatReader(Reader):
    """A second reader at an OpenAI-compatible `/chat/completions` endpoint."""

    default_provider = "openai_compat"

    def _call(self, prompt: str) -> str:
        key = self._key()
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        body = {"model": self.model, "temperature": 0, "max_tokens": 16,
                "messages": [{"role": "user", "content": prompt}]}
        ans = post_json(f"{self.base_url}/chat/completions", body, headers, self.timeout)
        try:
            return ans["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise ReaderCallError(f"{self.endpoint_host} answered without choices[0].message.content",
                                  "unreadable") from None
