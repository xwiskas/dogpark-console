"""Offline local-model client. The only module allowed to make network calls, and only to
localhost endpoints when a function here is actually invoked — never at import time, never
to any non-local host. Uses `urllib` only (stdlib); no API keys, no external hosts.

Both public functions degrade to built-in canned guidance if no local endpoint answers
within a short timeout, so the GUI never blocks waiting on the network.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Optional

AI_PREFIX = "AI-suggested — verify before running"

DEFAULT_ENDPOINTS = ["http://127.0.0.1:11434", "http://127.0.0.1:8642"]
DEFAULT_MODEL = "nemotron-3.5-lightning"
TIMEOUT_SECONDS = 3


def _is_local_endpoint(url: str) -> bool:
    return "127.0.0.1" in url or "localhost" in url


def _post_json(url: str, payload: dict, timeout: int = TIMEOUT_SECONDS) -> Optional[dict]:
    """POST JSON to a localhost-only URL and return the parsed JSON response, or None on
    any failure (timeout, connection refused, bad JSON, non-local URL)."""
    if not _is_local_endpoint(url):
        return None
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


class LLMClient:
    """Auto-detects a local Ollama or Hermes/OmniRoute-style endpoint. Every call is
    best-effort and falls back to canned text — it never raises and never blocks long."""

    def __init__(self, endpoints: Optional[list[str]] = None, model: Optional[str] = None):
        self.endpoints = list(endpoints) if endpoints else list(DEFAULT_ENDPOINTS)
        self.model = model or DEFAULT_MODEL

    @classmethod
    def from_config(cls, config: dict) -> "LLMClient":
        llm_cfg = config.get("llm", {}) if config else {}
        return cls(endpoints=llm_cfg.get("endpoints"), model=llm_cfg.get("model"))

    def _chat(self, system: str, user: str) -> Optional[str]:
        for base in self.endpoints:
            if not _is_local_endpoint(base):
                continue
            # Try Ollama's OpenAI-compatible endpoint first.
            resp = _post_json(
                f"{base.rstrip('/')}/v1/chat/completions",
                {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                },
            )
            if resp:
                try:
                    return resp["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError):
                    pass
            # Fall back to Ollama's native chat endpoint.
            resp = _post_json(
                f"{base.rstrip('/')}/api/chat",
                {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                },
            )
            if resp:
                try:
                    return resp["message"]["content"]
                except (KeyError, TypeError):
                    pass
        return None

    def explain(self, output_text: str, context: str = "") -> str:
        """Plain-English read of a tool's output. Falls back to a canned note if no local
        model answers."""
        system = (
            "You explain pentest tool output in plain English for a student in an authorized "
            "lab exercise. Be concise and factual. Do not suggest commands here."
        )
        user = f"Context: {context}\n\nTool output:\n{output_text[:4000]}"
        reply = self._chat(system, user)
        if reply:
            return reply.strip()
        return (
            "[No local LLM reachable — canned guidance] Review the output above for service "
            "names/versions, open ports, usernames, and error messages; cross-reference "
            "anything unfamiliar against the tool's man page before acting on it."
        )

    def suggest_next(self, state: dict) -> str:
        """Next-step ideas as text only, always prefixed with the AI-suggested disclaimer and
        constrained to in-scope targets + current phase."""
        phase = state.get("phase", "unknown")
        target = state.get("target", "unknown")
        last_action = state.get("last_action", "none")
        system = (
            "You suggest the next 1-3 reconnaissance/enumeration steps for an authorized "
            "university cyberlab pentest exercise. Only ever suggest actions against targets "
            "the user says are in scope for the current phase. Never suggest destructive, "
            "DoS, or flooding actions. Output plain text, no commands to auto-run."
        )
        user = (
            f"Current phase: {phase}\nCurrent target: {target}\nLast action run: {last_action}\n"
            "What should the student consider trying next?"
        )
        reply = self._chat(system, user)
        if reply:
            body = reply.strip()
        else:
            body = (
                f"[No local LLM reachable — canned guidance] For phase {phase} against "
                f"{target}, consider: confirming open services with a version scan, enumerating "
                "any web/SMB services found, and checking for null-session or default-credential "
                "exposure before moving to authenticated enumeration."
            )
        return f"{AI_PREFIX}: {body}"
