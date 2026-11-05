"""Evidence helpers: session-recording command builder, findings store, time-to-compromise
tracking, password/hash redaction, and a screenshot-reminder hook.

Stdlib only; all state lives in plain JSONL files under the configured output dir. No network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def script_command(output_dir: str, day: int) -> str:
    """Build the `script -a` command the student should run at the start of the day to
    capture a full terminal transcript alongside the app's own per-run logs."""
    return f"script -a {output_dir}/session/day{day}_terminal.log"


@dataclass
class Finding:
    id: str
    time: str
    target: str
    severity: str
    title: str
    evidence_path: str
    impact: str
    remediation: str


class FindingsStore:
    """Append-only JSONL store of findings, one engagement per output dir."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir).expanduser()
        self.path = self.output_dir / "findings.jsonl"

    def add(
        self,
        target: str,
        severity: str,
        title: str,
        evidence_path: str = "",
        impact: str = "",
        remediation: str = "",
    ) -> Finding:
        if severity not in SEVERITIES:
            severity = "Info"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        existing = self.all()
        finding = Finding(
            id=f"F{len(existing) + 1:03d}",
            time=datetime.now(timezone.utc).isoformat(),
            target=target,
            severity=severity,
            title=title,
            evidence_path=evidence_path,
            impact=impact,
            remediation=remediation,
        )
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(finding)) + "\n")
        return finding

    def all(self) -> list[Finding]:
        if not self.path.exists():
            return []
        findings = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                findings.append(Finding(**data))
        return findings


class TimeToCompromiseTracker:
    """Tracks first-contact and compromise timestamps per machine so the report can show
    time-to-compromise and time-to-Domain-Admin."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir).expanduser()
        self.path = self.output_dir / "ttc.jsonl"

    def mark(self, machine: str, event: str) -> dict:
        """event is a free-text label, e.g. 'first_contact', 'initial_access', 'domain_admin'."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "machine": machine,
            "event": event,
            "time": datetime.now(timezone.utc).isoformat(),
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def all(self) -> list[dict]:
        if not self.path.exists():
            return []
        records = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records


# Patterns that commonly show up as secrets in tool output. Best-effort, not exhaustive —
# this is a courtesy redaction before screenshots/reports, not a security control.
_REDACT_PATTERNS = [
    # password-ish key=value or key: value pairs
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(-p|--password)\s+\S+"),
    # NTLM/LM hash pairs as dumped by secretsdump: user:rid:lm:ntlm:::
    re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b"),
    # bare 32/40/64-hex hashes (md5/sha1/sha256-ish)
    re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
]


def redact(text: str) -> str:
    """Mask obvious passwords/hashes in a block of text before it goes in a screenshot or
    report. Conservative — prefer over-redacting to leaking a credential."""
    if not text:
        return text
    redacted = text
    for pattern in _REDACT_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def screenshot_reminder(action_label: str) -> str:
    """Returns a short reminder string the GUI can show after a notable action."""
    return (
        f"Reminder: screenshot the evidence for '{action_label}' now "
        "(proof-of-access, loot, or the finding) before moving on."
    )
