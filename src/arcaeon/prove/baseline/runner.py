"""Pluggable runners: anything that turns a prompt string into an answer
string. The library ships two — `CmdRunner` (shell out, stdin in / stdout
out) and `CallableRunner` (wrap a Python function) — and defines the
`Runner` protocol so you can write your own (an SDK client, an HTTP call,
whatever the substrate under test actually is).
"""
from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from typing import Callable


class RunnerError(Exception):
    """A runner failed to produce an answer (crash, timeout, nonzero exit)."""


class Runner(ABC):
    """Anything that answers a prompt. Implement `run`; that's the contract."""

    @abstractmethod
    def run(self, prompt: str) -> str:
        """Return the raw answer text for `prompt`. Raise RunnerError on failure."""
        raise NotImplementedError

    def describe(self) -> dict:
        """Provenance metadata recorded into registrations/comparisons."""
        return {"type": self.__class__.__name__}


class CmdRunner(Runner):
    """Shell out: `cmd` receives the prompt on stdin, its stdout is the answer.

    Works with anything speaking that convention — `ollama run <model>`,
    a one-shot wrapper around an API client, a live CLI relay script. Stdout
    only; stderr is captured for the error message on failure but never
    scored (this is deliberate — a chatty model that logs progress to stderr
    shouldn't have that noise scored as part of its answer).
    """

    def __init__(self, cmd: str, timeout: float = 120.0):
        self.cmd = cmd
        self.timeout = timeout

    def describe(self) -> dict:
        return {"type": "cmd", "cmd": self.cmd, "timeout": self.timeout}

    def run(self, prompt: str) -> str:
        try:
            proc = subprocess.run(
                self.cmd, shell=True, input=prompt, capture_output=True,
                text=True, timeout=self.timeout, encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired as e:
            raise RunnerError(
                f"runner timed out after {self.timeout}s: {self.cmd!r}") from e
        except OSError as e:
            raise RunnerError(f"runner failed to launch: {self.cmd!r}: {e}") from e
        if proc.returncode != 0:
            stderr_tail = (proc.stderr or "")[-2000:]
            raise RunnerError(
                f"runner exited {proc.returncode}: {self.cmd!r}\n"
                f"stderr (tail): {stderr_tail}")
        return proc.stdout


class CallableRunner(Runner):
    """Wrap any `str -> str` Python callable as a Runner (in-process, no shell)."""

    def __init__(self, fn: Callable[[str], str], label: str = "callable"):
        self.fn = fn
        self.label = label

    def describe(self) -> dict:
        return {"type": "callable", "label": self.label}

    def run(self, prompt: str) -> str:
        try:
            return self.fn(prompt)
        except Exception as e:  # noqa: BLE001 - deliberately wrap any failure
            raise RunnerError(f"callable runner {self.label!r} raised: {e}") from e
