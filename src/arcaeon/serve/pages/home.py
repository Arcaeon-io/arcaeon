# SPDX-License-Identifier: MIT
"""GET /: the dashboard's home page (K100)."""
from __future__ import annotations

from arcaeon.serve.pages import common

METHODS = ("GET",)


def page() -> str:
    return common.fill("index.html", active="/", title="Arcaeon on this machine")


def render(req) -> tuple[int, str]:
    return 200, page()
