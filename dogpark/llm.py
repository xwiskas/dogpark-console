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
CANNED_PREFIX = "[No local LLM reachable — canned guidance]"

DEFAULT_ENDPOINTS = ["http://127.0.0.1:11434", "http://127.0.0.1:8642"]
DEFAULT_MODEL = "nemotron-3.5-lightning"
TIMEOUT_SECONDS = 3
CHAT_HISTORY_CAP = 12

# System prompt for the chat panel's stealth-first recon advisor. Deliberately mirrors the
# rules in AGENTS.md so the on-box model and the console agree on what's safe to suggest.
RECON_CHAT_SYSTEM = (
    "You are the on-box AI recon advisor inside the DOGPARK Console, helping a student during "
    "an authorized, isolated CSUSB university cyberlab red-team/blue-team class exercise. "
    "Staying undetected by the blue team is a scored objective, so your advice must always "
    "put RECON FIRST, in this order: (1) passive/quiet host discovery, (2) service/version "
    "enumeration, (3) targeted enumeration — only after that consider anything louder. "
    "PREFER quiet commands (slow timing, rate limiting, null-session/passive enumeration, "
    "offline cracking). WARN clearly before suggesting anything loud (full/aggressive scans, "
    "password sprays, brute force, authenticated code execution) and explain why it's noisier. "
    "Only ever discuss targets on the authorized in-scope RFC1918 lab subnet; if scope is "
    "unclear, say so and ask instead of guessing. NEVER suggest reaching the internet or "
    "anything off this box, and NEVER suggest destructive, DoS, flooding, or wiping actions. "
    "When recommending a step, name the exact console button/action label if one matches "
    "(see the catalog below) so the student can find it in the tree. You never run anything "
    "yourself — the student always reviews and clicks Run manually. Keep answers concise and "
    "practical."
)


def _catalog_summary(limit: int = 24) -> str:
    """Compact 'Tool: action label [risk]' catalog built from dogpark.tools.TOOLS, so the
    chat system prompt can point the model at real console buttons instead of inventing
    command names. Discovery/quiet actions are listed first since those are the ones a
    stealth-first recon answer should lean on."""
    from dogpark import tools as _tools

    quiet_first: list[str] = []
    others: list[str] = []
    for tool in _tools.all_tools():
        for action in tool.actions:
            entry = f"- {tool.name}: {action.label} [{action.risk}]"
            if action.risk == "quiet" or tool.category == "discovery":
                quiet_first.append(entry)
            else:
                others.append(entry)
    ordered = quiet_first + others
    return "\n".join(ordered[:limit])


def canned_recon_plan() -> str:
    """Built-in stealthy-recon plan used when no local model answers, so the chat panel is
    still useful offline. References the console's own quiet/discovery action labels."""
    return (
        f"{CANNED_PREFIX} Stealthy recon order for the in-scope subnet:\n"
        "1. Passive ARP/neighbor read — 'ARP/neighbor table note (ip neigh)': zero packets sent.\n"
        "2. Quiet host discovery — 'Ping sweep (-sn)' or 'Broadcast discovery scripts (arp-scan "
        "alternative)' to find live hosts without a port scan.\n"
        "3. Passive capture alongside — 'Capture to file' (tcpdump) or 'Monitor interface' "
        "(arpwatch) to watch for blue-team activity without sending more traffic.\n"
        "4. Slow, targeted service scan on hosts you found — 'Quiet top-ports scan (-T2 -sS)', "
        "only the ports you actually need.\n"
        "5. Null-session/passive service enum on anything found — 'Null-session enumeration' "
        "(enum4linux) or 'List shares (null session)' (smbclient) — no creds, no lockout risk.\n"
        "6. Only once you accept the detection risk: move to louder, authenticated, or "
        "full-range scans (e.g. 'Full version+scripts scan (-T4 -A)').\n"
        "Verify every command before running it — nothing here auto-executes."
    )


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

    def chat(self, messages: list[dict], extra_system: str = "") -> Optional[str]:
        """Multi-turn chat for the AI recon-advisor panel. Posts an OpenAI-style `messages`
        list (role/content dicts) through the SAME localhost-only `_post_json` calls and
        `_is_local_endpoint` guard as `_chat` — this never reaches past loopback. `extra_system`
        carries the live operator context (scope/phase/target); the fixed recon-advisor system
        prompt plus a compact command catalog are always prepended. Returns None on any
        failure so the caller can fall back to `canned_recon_plan()`."""
        system = RECON_CHAT_SYSTEM + "\n\nCommand catalog (name real buttons by these labels):\n" + _catalog_summary()
        if extra_system:
            system = system + "\n\n" + extra_system

        trimmed = [m for m in messages if m.get("role") in ("user", "assistant") and m.get("content")]
        trimmed = trimmed[-CHAT_HISTORY_CAP:]
        payload_messages = [{"role": "system", "content": system}] + trimmed

        for base in self.endpoints:
            if not _is_local_endpoint(base):
                continue
            resp = _post_json(
                f"{base.rstrip('/')}/v1/chat/completions",
                {"model": self.model, "messages": payload_messages, "stream": False},
            )
            if resp:
                try:
                    return resp["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError):
                    pass
            resp = _post_json(
                f"{base.rstrip('/')}/api/chat",
                {"model": self.model, "messages": payload_messages, "stream": False},
            )
            if resp:
                try:
                    return resp["message"]["content"]
                except (KeyError, TypeError):
                    pass
        return None
