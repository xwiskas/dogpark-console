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
    """True only if the URL's host is a genuine loopback address.

    This is the guardrail that keeps the AI helper on-box: in a red/blue lab exercise the
    tool must never send recon data, output, or prompts off the Kali VM, where a blue-team
    sensor could see it. A substring match ("127.0.0.1" in url) is unsafe — e.g.
    http://127.0.0.1.evil.com/ or http://host/?x=localhost would slip through — so we parse
    the host and verify it is loopback (127.0.0.0/8, ::1, or the literal name 'localhost').
    Anything else, or an unparseable URL, is refused.
    """
    import ipaddress
    from urllib.parse import urlparse

    try:
        host = urlparse(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
            "You explain pentest tool output in plain English for a student in an authorized, "
            "isolated university cyberlab red-team/blue-team exercise. Be concise and factual. "
            "Do not suggest commands here. If the output suggests the activity was noisy or likely "
            "logged by a defender, say so briefly, since staying undetected by the blue team is "
            "part of the exercise."
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
            "You suggest the next 1-3 reconnaissance/enumeration steps for an authorized, "
            "isolated university cyberlab red-team/blue-team exercise. Staying undetected by the "
            "blue team is a scored objective, so PREFER low-and-slow, quiet options (slow timing, "
            "rate limiting, null-session/passive enumeration, offline cracking) and explicitly "
            "WARN when a step is noisy or likely to be logged/alerted (full-range or aggressive "
            "scans, password sprays, service brute force, authenticated code execution). Only ever "
            "suggest actions against targets the user says are in scope for the current phase, on "
            "the private lab network. Never suggest reaching the internet or anything off the lab, "
            "and never destructive, DoS, or flooding actions. Output plain text, no commands to "
            "auto-run — the student verifies and runs everything manually."
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
                f"{target}, stay quiet first: a slow/polite version scan of only the ports you "
                "need, then null-session or passive enumeration of any web/SMB services found, "
                "and offline checks before anything authenticated. Save louder moves (full-range "
                "or aggressive scans, sprays, brute force) for when you accept the detection risk."
            )
        return f"{AI_PREFIX}: {body}"
