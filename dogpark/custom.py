"""User- and AI-added commands.

The Kali box runs a local AI assistant during the exercise. This module lets that assistant
(and the operator) grow the console's command library at runtime WITHOUT writing or executing
code: new commands are plain data in a JSON file that the GUI loads into the same Action model
as the built-in catalog. Everything added here is still subject to the console's non-negotiable
rules — the scope lock, the manual-run gate (the operator reviews and clicks Run), and a safety
screen below that refuses destructive/DoS templates. Added commands are grouped under a clearly
labelled "Custom (AI / your additions)" node so they are never mistaken for the vetted catalog.

The AI adds a command by either appending to the JSON file directly or calling this module as a
CLI:

    python3 -m dogpark.custom --tool nmap --label "UDP top-50 quiet" --phase 1 --risk quiet \
        --template "nmap -sU --top-ports 50 -T2 {target} -oA {output}/udp_{target}" \
        --needs target output --description "Quiet UDP sweep of the 50 most common UDP ports."
"""

from __future__ import annotations

import json
import os
from typing import Optional

from dogpark.tools import Action, RISK_LEVELS

CUSTOM_GROUP = "Custom (AI / your additions)"

# Templates containing any of these are refused — the console never hosts destructive/DoS/
# wipe commands, no matter who adds them. Best-effort, case-insensitive substring screen.
_BANNED_SUBSTRINGS = (
    "dos", "flood", "hping3", "slowloris", "--max-rate 0", "-t0 ", "ddos",
    ":(){", "fork bomb", "rm -rf /", "rm -rf ~", "mkfs", "dd if=/dev/zero",
    "dd if=/dev/random", "> /dev/sd", "shutdown", "reboot", "halt ", "poweroff",
    ":>/dev/sd", "wipefs", "fdisk", "chmod -r 000 /",
)

_REQUIRED_FIELDS = ("label", "template")


def default_path() -> str:
    """Where custom commands live by default: alongside the engagement output under ~/dogpark."""
    base = os.environ.get("DOGPARK_HOME") or os.path.join(os.path.expanduser("~"), "dogpark")
    return os.path.join(base, "custom_actions.json")


def screen_template(template: str) -> Optional[str]:
    """Return a refusal reason if the template looks destructive, else None."""
    if not template or not template.strip():
        return "empty template"
    low = template.lower()
    for bad in _BANNED_SUBSTRINGS:
        if bad in low:
            return f"template contains banned/destructive token {bad!r}"
    return None


def _to_action(entry: dict) -> Action:
    """Build an Action from a custom JSON entry, applying defaults and namespacing the id."""
    raw_id = str(entry.get("id") or entry.get("label", "cmd")).strip().replace(" ", "_").lower()
    action_id = raw_id if raw_id.startswith("custom.") else f"custom.{raw_id}"
    risk = entry.get("risk", "normal")
    if risk not in RISK_LEVELS:
        risk = "normal"
    needs = entry.get("needs", ())
    if isinstance(needs, list):
        needs = tuple(needs)
    note = entry.get("notes", "")
    tag = "[custom — not vetted by the built-in catalog] "
    return Action(
        id=action_id,
        label=entry["label"],
        phase=int(entry.get("phase", 1)),
        description=tag + str(entry.get("description", "")).strip(),
        risk=risk,
        template=entry["template"],
        needs=needs,
        notes=note,
    )


def validate(entry: dict) -> Optional[str]:
    """Return a reason the entry is invalid/unsafe, or None if it is acceptable."""
    for field in _REQUIRED_FIELDS:
        if not entry.get(field):
            return f"missing required field {field!r}"
    if not isinstance(entry.get("needs", []), (list, tuple)):
        return "'needs' must be a list"
    bad = screen_template(entry["template"])
    if bad:
        return bad
    return None


def load_custom_actions(path: Optional[str] = None) -> tuple[Action, ...]:
    """Load custom commands from the JSON store. Invalid/unsafe entries are skipped silently so
    one bad entry never breaks the tool. Returns a tuple of Actions (possibly empty)."""
    path = path or default_path()
    if not os.path.exists(path):
        return ()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return ()
    entries = data.get("actions", data) if isinstance(data, dict) else data
    if not isinstance(entries, list):
        return ()
    out: list[Action] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or validate(entry):
            continue
        action = _to_action(entry)
        if action.id in seen:
            continue
        seen.add(action.id)
        out.append(action)
    return tuple(out)


def add_custom_action(entry: dict, path: Optional[str] = None) -> tuple[bool, str]:
    """Validate, safety-screen, and append a custom command to the JSON store.

    Returns (ok, message). This is the single supported way for the on-box AI or the operator
    to add a command — it refuses destructive templates and never executes anything.
    """
    reason = validate(entry)
    if reason:
        return False, f"refused: {reason}"
    path = path or default_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existing: list = []
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            existing = loaded.get("actions", loaded) if isinstance(loaded, dict) else loaded
            if not isinstance(existing, list):
                existing = []
        except (OSError, ValueError):
            existing = []
    existing.append(entry)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"actions": existing}, fh, indent=2)
    return True, f"added '{entry['label']}' to {path}"


def _main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Add a custom command to the DOGPARK console.")
    p.add_argument("--tool", default="custom", help="(informational) tool group the command relates to")
    p.add_argument("--id")
    p.add_argument("--label", required=True)
    p.add_argument("--phase", type=int, default=1)
    p.add_argument("--risk", default="normal", choices=list(RISK_LEVELS))
    p.add_argument("--template", required=True, help="command with {placeholders}")
    p.add_argument("--needs", nargs="*", default=[])
    p.add_argument("--description", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--path", default=None)
    args = p.parse_args(argv)
    entry = {
        "tool": args.tool, "id": args.id, "label": args.label, "phase": args.phase,
        "risk": args.risk, "template": args.template, "needs": args.needs,
        "description": args.description, "notes": args.notes,
    }
    ok, msg = add_custom_action(entry, args.path)
    print(msg)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(_main())
